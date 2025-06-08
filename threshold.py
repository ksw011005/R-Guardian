def determine_entropy(ext: str, entropy: float) -> bool:
    extension = ext
    # 파일 유형별 엔트로피 임계값
    thresholds = {
        '.txt': 0.55, #원래는 7.8
        '.doc': 0.78,
        '.docx': 0.78,
        '.xls': 0.79,
        '.xlsx': 0.79,
        '.ppt': 0.78,
        '.pptx': 0.78,
        '.hwp': 0.78,
        '.pdf': 0.79,
        '.jpg': 0.75,
        '.jpeg': 0.75,
        '.png': 0.78,
        '.exe': 0.79,
        '.zip': 0.79,
        '.dll': 0.78
    }

    threshold = thresholds[extension]
    print(threshold)
    return entropy >= threshold
