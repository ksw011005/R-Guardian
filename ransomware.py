import os
import shutil
import time
import psutil
import sys
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy import is_suspicious_entropy

BLOCKLIST_PATH = "blocked_programs.txt"

def require_sudo():
    if os.geteuid() != 0:
        print("[INFO] 관리자 권한이 필요합니다. sudo로 재실행합니다...")
        try:
            os.execvp("sudo", ["sudo", "python3"] + sys.argv)
        except Exception as e:
            print(f"[ERROR] sudo 재실행 실패: {e}")
            sys.exit(1)

def log(message):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{timestamp} {message}")

def block_program(exe_path):
    if not is_blocked(exe_path):
        with open(BLOCKLIST_PATH, 'a') as f:
            f.write(f"{exe_path}\n")
        log(f"[INFO] 실행 파일 차단 목록에 추가됨: {exe_path}")

def is_blocked(exe_path):
    if not os.path.exists(BLOCKLIST_PATH):
        return False
    with open(BLOCKLIST_PATH, 'r') as f:
        blocked_list = f.read().splitlines()
    return exe_path in blocked_list

def kill_and_block_process(proc):
    try:
        exe_path = proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
        log(f"[WARNING] 프로세스 exe 경로 접근 불가: {e}")
        return False

    if not exe_path:
        log("[WARNING] 프로세스 실행 경로가 없습니다.")
        return False

    if is_blocked(exe_path):
        log(f"[INFO] 이미 차단된 실행 파일: {exe_path}")
        return False

    try:
        proc.kill()
        log(f"[ACTION] 프로세스 종료 성공: PID={proc.pid}, EXE={exe_path}")
    except psutil.AccessDenied:
        log(f"[ERROR] 프로세스 종료 권한 부족: PID={proc.pid}, EXE={exe_path}")
        return False
    except psutil.NoSuchProcess:
        log(f"[INFO] 프로세스 이미 종료됨: PID={proc.pid}")
        return True
    except Exception as e:
        log(f"[ERROR] 프로세스 종료 중 오류: {e}")
        return False

    block_program(exe_path)
    return True

def get_pids_accessing_file_lsof(target_path):
    try:
        output = subprocess.check_output(['lsof', target_path], stderr=subprocess.DEVNULL, text=True)
        pids = set()
        for line in output.splitlines()[1:]:  # 첫 줄은 헤더
            parts = line.split()
            if len(parts) >= 2:
                pid_str = parts[1]
                if pid_str.isdigit():
                    pids.add(int(pid_str))
        return pids
    except subprocess.CalledProcessError:
        # 파일에 접근중인 프로세스 없음
        return set()


def get_pids_accessing_file(target_path):
    # psutil 버전
    pids = set()
    for proc in psutil.process_iter(['pid', 'open_files']):
        try:
            open_files = proc.info['open_files']
            if open_files:
                for f in open_files:
                    if f.path == target_path:
                        pids.add(proc.pid)
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if pids:
        return pids

    # psutil로 못찾으면 lsof 시도
    return get_pids_accessing_file_lsof(target_path)


def kill_blocked_programs():
    if not os.path.exists(BLOCKLIST_PATH):
        return
    with open(BLOCKLIST_PATH, 'r') as f:
        blocked = f.read().splitlines()
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            exe = proc.info['exe']
            if exe and exe in blocked:
                proc.kill()
                log(f"[BLOCK] 차단된 프로그램 실행 감지 → 종료: {exe}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

class ChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

        filepath = event.src_path

        if '.bak' in filepath:
            return

        if not filepath or not os.path.exists(filepath):
            log("[WARNING] 유효하지 않은 파일 경로 감지. 무시함.")
            return

        log(f"[INFO] 변경 감지: {filepath}")

        bak_path = filepath + ".bak"
        try:
            if not os.path.exists(bak_path):
                shutil.copy2(filepath, bak_path)
                log(f"[INFO] 백업 생성: {bak_path}")
        except Exception as e:
            log(f"[ERROR] 백업 실패: {e}")
            return

        try:
            suspicious = is_suspicious_entropy(filepath)
        except Exception as e:
            log(f"[ERROR] 엔트로피 검사 오류: {e}")
            return

        if suspicious:
            log(f"[ALERT] 의심스러운 파일 변경 감지됨: {filepath}")

            pids = get_pids_accessing_file(filepath)
            if not pids:
                log("[INFO] 변경 파일에 접근 중인 프로세스가 없습니다.")
                return

            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    kill_and_block_process(proc)
                except psutil.NoSuchProcess:
                    log(f"[INFO] PID {pid} 프로세스가 이미 종료됨.")
                except Exception as e:
                    log(f"[ERROR] PID {pid} 프로세스 처리 중 오류: {e}")
        else:
            log(f"[INFO] 정상적인 파일 변경: {filepath}")

def main():
    require_sudo()

    folder_path = input("감시할 폴더 경로를 입력하세요: ").strip()
    if not os.path.isdir(folder_path):
        print("[ERROR] 유효한 폴더 경로가 아닙니다.")
        return

    log(f"[INFO] 감시 시작: {folder_path}")

    observer = Observer()
    event_handler = ChangeHandler()
    observer.schedule(event_handler, folder_path, recursive=True)
    observer.start()

    try:
        while True:
            kill_blocked_programs()
            time.sleep(1)
    except KeyboardInterrupt:
        log("[INFO] 감시 종료 중...")
        observer.stop()
    observer.join()
    log("[INFO] 프로그램 종료됨.")

if __name__ == "__main__":
    main()
