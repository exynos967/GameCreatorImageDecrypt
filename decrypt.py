import os
from PIL import Image
import numpy as np
from multiprocessing import Pool, Manager
from io import BytesIO
import zipfile

try:
    import pyzipper  # 可选：用于处理 AES 加密 ZIP
except Exception:  # noqa: BLE001
    pyzipper = None


def is_valid_png(data):
    """使用 Pillow 判断文件是否是有效的 PNG 文件"""
    try:
        img = Image.open(BytesIO(data))
        img.verify()
        return True
    except (IOError, SyntaxError):
        return False


def is_valid_ogg(data: bytes) -> bool:
    """最小 OGG 校验：以 'OggS' 开头"""
    return len(data) >= 4 and data[:4] == b"OggS"


def is_valid_mp3(data: bytes) -> bool:
    """最小 MP3 校验：'ID3' 标签或扫描到帧同步 0xFFE?（前 16KB）"""
    if len(data) < 2:
        return False
    # ID3 标签
    if data[:3] == b"ID3":
        return True
    # 扫描同步字（允许前部有少量垃圾字节）
    limit = min(len(data) - 1, 16 * 1024)
    for i in range(limit):
        if data[i] == 0xFF and (data[i + 1] & 0xE0) == 0xE0:
            return True
    return False


def is_valid_wav(data: bytes) -> bool:
    """可选 WAV 校验：'RIFF' ... 'WAVE'"""
    return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE"


def try_decrypt(encrypted_data, candidate_index, swap_pair=(1, 2)):
    """尝试用给定的候选位置解密

    参数:
    - candidate_index: 待删除的下标（单字节）
    - swap_pair: 交换的下标对；为 None 表示不交换
    """
    arr = np.array(list(encrypted_data), dtype=np.uint8)
    if swap_pair is not None:
        a, b = swap_pair
        if max(a, b) < arr.size:
            arr[a], arr[b] = arr[b], arr[a]
    if 0 <= candidate_index < arr.size:
        arr = np.delete(arr, candidate_index)
    return bytes(arr)


def brute_force_single_decrypt(args):
    """每个进程解密单个候选位置"""
    encrypted_data, candidate_index, result, validator, swap_pair = args

    decrypted_data = try_decrypt(encrypted_data, candidate_index, swap_pair)

    if validator(decrypted_data):
        result.put(decrypted_data)
        return candidate_index

    return None


def brute_force_decrypt_png(input_file_path, output_file_path, validator=is_valid_png):
    """穷举解密 PNG/通用文件（通过 validator 断言）"""
    with open(input_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    ones_indices = [i for i, byte in enumerate(encrypted_data) if byte == 1]
    print(f"找到 {len(ones_indices)} 个候选的 `0x01` 字节位置，开始尝试解密...")

    with Manager() as manager:
        result = manager.Queue()

        def attempt(candidates, swap_pair):
            if not candidates:
                return False
            with Pool(processes=os.cpu_count()) as pool:
                pool.map(
                    brute_force_single_decrypt,
                    [
                        (encrypted_data, index, result, validator, swap_pair)
                        for index in candidates
                    ],
                )
            if not result.empty():
                decrypted_data = result.get()
                with open(output_file_path, "wb") as output_file:
                    output_file.write(decrypted_data)
                print(f"解密成功，文件已保存至 {output_file_path}")
                return True
            return False

        # 层级 1：默认规则（交换 1/2）+ 0x01 候选
        if attempt(ones_indices, (1, 2)):
            return
        # 层级 2：不交换头部 + 0x01 候选
        print("回退：尝试不交换头部 + 0x01 候选…")
        if attempt(ones_indices, None):
            return
        # 层级 3：扩大候选范围到前 64KB 的所有位置（防止音频中未使用 0x01 作哨兵）
        max_scan = min(len(encrypted_data), 64 * 1024)
        range_candidates = list(range(max_scan))
        print(f"回退：尝试交换 1/2 + 前 {max_scan} 字节的任意删除…（可能较慢）")
        if attempt(range_candidates, (1, 2)):
            return
        print("回退：尝试不交换头部 + 前缀任意删除…（可能较慢）")
        if attempt(range_candidates, None):
            return

    print("未能成功解密文件，请检查文件或加密算法。")


def detect_and_decrypt_ogg(input_file_path: str, output_file_path: str) -> bool:
    """针对 OGG 的快速探测式解密：
    1) 小范围交换头部字节 + 删除前 16 个位置之一
    2) 全文件 XOR 常量 1..255（先对前 4 字节验证 'OggS'）
    命中即写出并返回 True；否则返回 False
    """
    with open(input_file_path, "rb") as f:
        data = f.read()

    def write_if_ogg_like(cbytes: bytes, note: str) -> bool:
        if is_valid_ogg(cbytes):
            with open(output_file_path, "wb") as w:
                w.write(cbytes)
            print(f"探测命中：{note} → {output_file_path}")
            return True
        # 容忍前缀少量噪声：若在前 8KB 出现 'OggS'，则切掉前缀
        pos = cbytes.find(b"OggS", 1, min(len(cbytes), 8192))
        if pos != -1:
            with open(output_file_path, "wb") as w:
                w.write(cbytes[pos:])
            print(f"探测命中（切前缀{pos}字节）：{note} → {output_file_path}")
            return True
        return False

    # 0. 原始就有效或近似有效
    if write_if_ogg_like(data, "原始"):
        return True

    # 1A. 头部小范围交换 + 删除前缀一个字节（0..15） → 直接魔数匹配
    swaps = [None, (0, 1), (1, 2), (2, 3), (0, 2), (0, 3)]
    max_del = min(len(data), 16)
    for sp in swaps:
        for del_idx in range(max_del):
            arr = bytearray(data)
            if sp is not None:
                a, b = sp
                if max(a, b) < len(arr):
                    arr[a], arr[b] = arr[b], arr[a]
            # 删除单个字节（前缀小窗口）
            del arr[del_idx]
            cand = bytes(arr)
            if write_if_ogg_like(cand, f"swap={sp} del_idx={del_idx}"):
                return True

    # 1B. 头部小范围交换 + 删除前缀一个字节（0..15） → 尝试 XOR/ADD 常量对齐 'OggS'
    header = b"OggS"
    for sp in swaps:
        for del_idx in range(max_del):
            arr = bytearray(data)
            if sp is not None:
                a, b = sp
                if max(a, b) < len(arr):
                    arr[a], arr[b] = arr[b], arr[a]
            del arr[del_idx]
            if len(arr) < 4:
                continue
            h = arr[:4]
            # XOR 常量：四个位置的 XOR 差必须相等
            c0 = h[0] ^ header[0]
            if (
                h[1] ^ header[1] == c0
                and h[2] ^ header[2] == c0
                and h[3] ^ header[3] == c0
            ):
                out = bytes(b ^ c0 for b in arr)
                if write_if_ogg_like(out, f"swap={sp} del_idx={del_idx} XOR={c0}"):
                    return True
            # ADD 常量（加法加密）：enc = orig + k → orig = enc - k
            k0 = (h[0] - header[0]) & 0xFF
            if (
                (h[1] - header[1]) & 0xFF == k0
                and (h[2] - header[2]) & 0xFF == k0
                and (h[3] - header[3]) & 0xFF == k0
            ):
                out = bytes((b - k0) & 0xFF for b in arr)
                if write_if_ogg_like(out, f"swap={sp} del_idx={del_idx} ADD={k0}"):
                    return True

    # 1C. 头部小范围交换 + 删除前缀两个字节（0..7 组合） → 直接魔数匹配
    max_del2 = min(len(data), 8)
    for sp in swaps:
        for d1 in range(max_del2):
            for d2 in range(d1 + 1, max_del2):
                arr = bytearray(data)
                if sp is not None:
                    a, b = sp
                    if max(a, b) < len(arr):
                        arr[a], arr[b] = arr[b], arr[a]
                # 注意先删较大的索引避免位移问题
                del arr[d2]
                del arr[d1]
                cand = bytes(arr)
                if write_if_ogg_like(cand, f"swap={sp} del2=({d1},{d2})"):
                    return True

    # 1D. 头部小范围交换 + 删除前缀两个字节 → 尝试 XOR/ADD 常量
    for sp in swaps:
        for d1 in range(max_del2):
            for d2 in range(d1 + 1, max_del2):
                arr = bytearray(data)
                if sp is not None:
                    a, b = sp
                    if max(a, b) < len(arr):
                        arr[a], arr[b] = arr[b], arr[a]
                del arr[d2]
                del arr[d1]
                if len(arr) < 4:
                    continue
                h = arr[:4]
                c0 = h[0] ^ header[0]
                if (
                    h[1] ^ header[1] == c0
                    and h[2] ^ header[2] == c0
                    and h[3] ^ header[3] == c0
                ):
                    out = bytes(b ^ c0 for b in arr)
                    if write_if_ogg_like(out, f"swap={sp} del2=({d1},{d2}) XOR={c0}"):
                        return True
                k0 = (h[0] - header[0]) & 0xFF
                if (
                    (h[1] - header[1]) & 0xFF == k0
                    and (h[2] - header[2]) & 0xFF == k0
                    and (h[3] - header[3]) & 0xFF == k0
                ):
                    out = bytes((b - k0) & 0xFF for b in arr)
                    if write_if_ogg_like(out, f"swap={sp} del2=({d1},{d2}) ADD={k0}"):
                        return True

    # 2. 尝试全文件 XOR 常量（先用前 4 字节判断是否可达 'OggS'）
    if len(data) >= 4:
        for c in range(1, 256):
            if bytes([data[i] ^ c for i in range(4)]) == b"OggS":
                out = bytes(b ^ c for b in data)
                if write_if_ogg_like(out, f"XOR 常量 {c}"):
                    return True

    return False


def brute_force_decrypt_ogg(input_file_path, output_file_path):
    """穷举解密 OGG 文件"""
    # 先走快速探测路径
    if detect_and_decrypt_ogg(input_file_path, output_file_path):
        return
    # 探测失败再走通用穷举（注意音频较大时会更慢）
    return brute_force_decrypt_png(input_file_path, output_file_path, is_valid_ogg)


def brute_force_decrypt_mp3(input_file_path, output_file_path):
    """穷举解密 MP3 文件"""
    return brute_force_decrypt_png(input_file_path, output_file_path, is_valid_mp3)


def decrypt_all_supported_in_folder(folder_path, output_folder):
    """遍历文件夹中的支持格式并进行解密：png、ogg、mp3"""
    supported = {
        ".png": brute_force_decrypt_png,
        ".ogg": brute_force_decrypt_ogg,
        ".mp3": brute_force_decrypt_mp3,
    }

    all_files = [
        f
        for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
    ]

    os.makedirs(output_folder, exist_ok=True)

    target_files = []
    for name in all_files:
        _, ext = os.path.splitext(name)
        if ext.lower() in supported:
            target_files.append(name)

    if not target_files:
        print("未在输入目录中找到支持的文件（png/ogg/mp3）。")
        return

    def try_extract_zip_container(in_path: str) -> bool:
        # ZIP 本地文件头签名：PK\x03\x04 （也可能是其他 PK* 签名）
        try:
            with open(in_path, "rb") as f:
                sig = f.read(4)
            if not (len(sig) == 4 and sig[:2] == b"PK"):
                return False

            def extract_with_reader(zf, pwd: bytes | None) -> bool:
                extracted = False
                for info in zf.infolist():
                    if getattr(info, "is_dir", lambda: False)():
                        continue
                    try:
                        data = zf.read(info, pwd=pwd) if pwd else zf.read(info)
                    except Exception:
                        continue
                    base = os.path.basename(info.filename)
                    out_path = os.path.join(output_folder, f"decrypted_{base}")
                    with open(out_path, "wb") as w:
                        w.write(data)
                    print(f"检测到 ZIP 容器，已解包：{out_path}")
                    extracted = True
                return extracted

            # 优先尝试已知默认密码（来自游戏 script.js/配置）：gc_zip_2024（AESZip）
            default_pw = b"gc_zip_2024"
            if pyzipper is not None:
                try:
                    with pyzipper.AESZipFile(in_path) as zf:
                        zf.pwd = default_pw
                        ok_any = False
                        for info in zf.infolist():
                            if getattr(info, "is_dir", lambda: False)():
                                continue
                            try:
                                data = zf.read(info)
                            except Exception:
                                continue
                            base = os.path.basename(info.filename)
                            out_path = os.path.join(output_folder, f"decrypted_{base}")
                            with open(out_path, "wb") as w:
                                w.write(data)
                            print(
                                "检测到 AES-ZIP 容器（默认密码命中: gc_zip_2024），已解包：",
                                out_path,
                            )
                            ok_any = True
                        if ok_any:
                            return True
                except Exception:
                    pass

            # 先尝试无密码/传统加密
            with zipfile.ZipFile(in_path) as zf:
                extracted = extract_with_reader(zf, None)
                if extracted:
                    return True

            # 若需要密码，尝试 passwords.txt 字典
            pwd_file = os.path.join(os.path.dirname(__file__), "passwords.txt")
            candidates: list[bytes] = []
            if os.path.exists(pwd_file):
                with open(pwd_file, "r", encoding="utf-8", errors="ignore") as pf:
                    for line in pf:
                        pw = line.strip()
                        if pw:
                            candidates.append(pw.encode("utf-8"))

            # 传统 ZipCrypto 解密尝试
            if candidates:
                with zipfile.ZipFile(in_path) as zf:
                    for pwd in candidates:
                        try:
                            if extract_with_reader(zf, pwd):
                                print(
                                    "字典命中（ZipCrypto）：密码=",
                                    pwd.decode("utf-8", "ignore"),
                                )
                                return True
                        except RuntimeError:
                            continue

            # AES 加密（需要 pyzipper）
            if pyzipper is not None and candidates:
                try:
                    with pyzipper.AESZipFile(in_path) as zf:
                        for pwd in candidates:
                            try:
                                zf.pwd = pwd
                                for info in zf.infolist():
                                    if getattr(info, "is_dir", lambda: False)():
                                        continue
                                    data = zf.read(info)
                                    base = os.path.basename(info.filename)
                                    out_path = os.path.join(
                                        output_folder, f"decrypted_{base}"
                                    )
                                    with open(out_path, "wb") as w:
                                        w.write(data)
                                    print(
                                        "检测到 AES-ZIP 容器，已解包：",
                                        out_path,
                                        " 密码=",
                                        pwd.decode("utf-8", "ignore"),
                                    )
                                    return True
                            except Exception:
                                continue
                except Exception:
                    pass

            if candidates and pyzipper is None:
                print(
                    "检测到受密码保护的 ZIP，但缺少 pyzipper 以支持 AES；"
                    "如需尝试 AES 密码字典，请安装 pyzipper 并提供 passwords.txt。"
                )
            if not candidates:
                print(
                    "检测到受密码保护的 ZIP（可能使用 deflate64/AES）。"
                    "请在项目根目录提供 passwords.txt（每行一个密码）以尝试解包。"
                )
            return False
        except zipfile.BadZipFile:
            return False

    for file_name in target_files:
        input_file = os.path.join(folder_path, file_name)
        output_file = os.path.join(output_folder, f"decrypted_{file_name}")
        print(f"开始解密文件: {input_file}")

        # 若文件实为 ZIP 容器，直接解包内部真实资源
        if try_extract_zip_container(input_file):
            print(f"处理完成: {input_file} → ZIP 解包完毕")
            continue

        decrypt_fn = supported[os.path.splitext(file_name)[1].lower()]
        decrypt_fn(input_file, output_file)
        print(f"处理完成: {output_file}")


if __name__ == "__main__":
    # 固定输入/输出目录：脚本同级的 input / output
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = os.path.join(script_dir, "input")
    output_folder = os.path.join(script_dir, "output")

    # 若不存在则自动创建
    os.makedirs(input_folder, exist_ok=True)
    os.makedirs(output_folder, exist_ok=True)

    decrypt_all_supported_in_folder(input_folder, output_folder)
