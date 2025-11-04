import os
from PIL import Image
import numpy as np
from multiprocessing import Pool, Manager
from io import BytesIO


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


def brute_force_decrypt_ogg(input_file_path, output_file_path):
    """穷举解密 OGG 文件"""
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

    for file_name in target_files:
        input_file = os.path.join(folder_path, file_name)
        output_file = os.path.join(output_folder, f"decrypted_{file_name}")
        print(f"开始解密文件: {input_file}")
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
