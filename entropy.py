import math
import os
from collections import Counter
from typing import Tuple
from threshold import determine_entropy

def read_file_bytes(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def chi_squared(data: bytes) -> float:
    if not data:
        return 0.0
    expected = len(data) / 256
    freq = Counter(data)
    return sum(((freq.get(byte, 0) - expected) ** 2) / expected for byte in range(256))

def serial_correlation(data: bytes) -> float:
    n = len(data)
    if n < 2:
        return 0.0
    avg = sum(data) / n
    num = sum((data[i] - avg) * (data[i - 1] - avg) for i in range(1, n))
    den = sum((b - avg) ** 2 for b in data)
    return num / den if den != 0 else 0.0

def monte_carlo_pi_error(data: bytes) -> float:
    if len(data) < 2:
        return 1.0
    samples = len(data) // 2
    inside = 0
    for i in range(samples):
        x = data[2 * i] / 255.0
        y = data[2 * i + 1] / 255.0
        if x * x + y * y <= 1.0:
            inside += 1
    estimated_pi = 4 * inside / samples
    return abs(math.pi - estimated_pi)

def arithmetic_mean(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(data) / len(data)

def normalize_metrics(ent, chi, corr, monte, mean):
    norm_ent = ent / 8
    norm_chi = 1 / (1 + chi)
    norm_corr = 1 - abs(corr)
    norm_monte = 1 / (1 + monte)
    norm_mean = 1 - abs((mean - 127.5) / 127.5)
    return norm_ent, norm_chi, norm_corr, norm_monte, norm_mean

def get_file_category(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return ext

def get_default_weights(file_type: str) -> Tuple[float, float, float, float, float]:
    if file_type == 'compressed':
        return (0.25, 0.3, 0.2, 0.15, 0.1)
    elif file_type == 'document':
        return (0.35, 0.25, 0.1, 0.15, 0.15)
    elif file_type == 'image':
        return (0.1, 0.3, 0.3, 0.25, 0.05)
    elif file_type == 'pe':
        return (0.35, 0.25, 0.2, 0.25, 0.2)
    else:  # 'other'
        return (0.3, 0.25, 0.25, 0.15, 0.1)

def compute_entropy(data: bytes, weights: Tuple[float, float, float, float, float]) -> float:
    ent = shannon_entropy(data)
    chi = chi_squared(data)
    corr = serial_correlation(data)
    monte = monte_carlo_pi_error(data)
    mean = arithmetic_mean(data)

    norm_ent, norm_chi, norm_corr, norm_monte, norm_mean = normalize_metrics(ent, chi, corr, monte, mean)

    w1, w2, w3, w4, w5 = weights
    entropy = (
        w1 * norm_ent +
        w2 * norm_chi +
        w3 * norm_corr +
        w4 * norm_monte +
        w5 * norm_mean
    ) / sum(weights)

    return entropy

def is_suspicious_entropy(filename: str, weights: Tuple[float, float, float, float, float] = None) -> bool:
    data = read_file_bytes(filename)
    ext = get_file_category(filename)
    if ext in ['.zip', '.rar', '.7z', '.gz', '.tar']:
        file_type = 'compressed'
    elif ext in ['.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx','.ppt', '.pptx', '.hwp']:
        file_type = 'document'
    elif ext in ['.jpg', '.jpeg', '.png']:
        file_type = 'image'
    elif ext in ['.exe', '.dll']:
        file_type = 'pe'
    else:
        file_type = 'other'
    
    if weights is None:
        weights = get_default_weights(file_type)
    entropy = compute_entropy(data, weights)
    print(entropy)
    print(determine_entropy(ext,entropy))
    #return determine_entropy(ext,entropy)
    return True
