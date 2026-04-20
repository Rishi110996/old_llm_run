import sys
import os
import re
import shutil
import subprocess
import magic
import argparse
import hashlib
import threading
import queue
import tempfile
import logging
from zipfile import ZipFile, BadZipFile

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("apk_dump_debug.log", mode='w'),
        logging.StreamHandler()
    ]
)

# Ensure stdout is line-buffered
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)


def resolve_apktool_command():
    apktool_jar = os.environ.get("APKTOOL_JAR")
    if apktool_jar:
        return ["java", "-jar", apktool_jar]

    apktool_bin = os.environ.get("APKTOOL_BIN") or shutil.which("apktool")
    if apktool_bin:
        return [apktool_bin]

    legacy_jar = r"D:\app_tools\apktool_2.12.0.jar"
    if os.path.exists(legacy_jar):
        return ["java", "-jar", legacy_jar]

    # Bundled apktool.bat shipped alongside this script in llm_V1/apktool/
    _here = os.path.dirname(os.path.abspath(__file__))
    bundled_bat = os.path.join(_here, "apktool", "apktool.bat")
    if os.path.isfile(bundled_bat):
        return [bundled_bat]

    return ["apktool"]


def resolve_keytool_command():
    keytool_bin = os.environ.get("KEYTOOL_BIN") or shutil.which("keytool")
    if keytool_bin:
        return [keytool_bin]

    legacy_bin = r"D:\app_tools\jdk-11\bin\keytool.exe"
    if os.path.exists(legacy_bin):
        return [legacy_bin]

    return ["keytool"]


def resolve_7zip_command():
    archive_bin = os.environ.get("SEVENZIP_BIN") or shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
    if archive_bin:
        return [archive_bin]

    common_paths = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for path in common_paths:
        if os.path.isfile(path):
            return [path]

    return None

class ApkDump:
    logs = False
    tempDir = ''
    md5List = []
    apkFilePath = ''
    apkDumpPath = ''
    apkFileName = ''
    apkDumpFilesList = []
    allFilesList = []
    apktool_cmd = None
    keytool_cmd = None
    sevenzip_cmd = None

    def __init__(self):
        self.tempDir = ''
        self.md5List = []
        self.apkFilePath = ''
        self.apkDumpPath = ''
        self.apkFileName = ''
        self.forceDump = True
        self.logs = False
        self.apkDumpFilesList = []
        self.apktool_cmd = resolve_apktool_command()
        self.keytool_cmd = resolve_keytool_command()
        self.sevenzip_cmd = resolve_7zip_command()

    def _extract_with_7zip(self, outputDir):
        if not self.sevenzip_cmd:
            return False

        cmd = list(self.sevenzip_cmd) + ['x', '-y', f'-o{outputDir}', self.apkFilePath]
        logging.info("Trying 7-Zip APK extraction fallback")
        logging.debug(f"Running 7-Zip command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                return True
            logging.warning("7-Zip extraction failed with code %s", result.returncode)
            if result.stdout:
                logging.debug("7-Zip stdout:\n%s", result.stdout)
            if result.stderr:
                logging.debug("7-Zip stderr:\n%s", result.stderr)
        except subprocess.TimeoutExpired:
            logging.warning("7-Zip extraction timed out")
        except Exception:
            logging.exception("7-Zip extraction raised an exception")

        return False

    def _extract_with_zipfile_best_effort(self, outputDir):
        extracted = 0
        skipped = 0
        logging.info("Trying best-effort ZipFile APK extraction fallback")
        try:
            with ZipFile(self.apkFilePath, 'r') as zipObj:
                for info in zipObj.infolist():
                    out_path = os.path.join(outputDir, info.filename)
                    try:
                        if info.is_dir():
                            os.makedirs(out_path, exist_ok=True)
                            continue

                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with zipObj.open(info, 'r') as src, open(out_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        extracted += 1
                    except (NotImplementedError, RuntimeError) as exc:
                        skipped += 1
                        logging.warning("Skipping ZIP entry %s: %s", info.filename, exc)
                    except Exception as exc:
                        skipped += 1
                        logging.warning("Failed extracting ZIP entry %s: %s", info.filename, exc)
        except BadZipFile:
            logging.exception("APK is not a valid ZIP archive")
            return False
        except Exception:
            logging.exception("Best-effort ZipFile extraction failed")
            return False

        logging.info("Best-effort ZIP extraction completed: %d extracted, %d skipped", extracted, skipped)
        return extracted > 0

    def fire_apk_tool(self, outputDir):
        apktoolFail = False
        cmd = list(self.apktool_cmd) + ['d', '-f', '-s', self.apkFilePath, '-o', outputDir]
        print(f"DEBUG: Running apktool command: {' '.join(cmd)}", flush=True)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            print("DEBUG: Apktool stdout:\n" + result.stdout, flush=True)

            if result.returncode != 0 or "Exception in thread" in result.stdout:
                print("APKTool failed, fallback to ZIP extraction", flush=True)
                apktoolFail = True

        except subprocess.TimeoutExpired:
            print("ERROR: APKTool command timed out.", flush=True)
            apktoolFail = True
        except Exception as e:
            print(f"ERROR: Exception while running apktool: {e}", flush=True)
            apktoolFail = True

        if apktoolFail:
            print("\nAPKTool FAILED to decode resources, extracting APK as ZIP...", flush=True)
            if self._extract_with_7zip(outputDir):
                return
            if self._extract_with_zipfile_best_effort(outputDir):
                return
            raise RuntimeError("APK extraction failed after apktool, 7-Zip, and ZipFile fallbacks")


    def get_cert_details(self):
        try:
            logging.info("Getting certificate details using keytool...")
            cmd = list(self.keytool_cmd) + ['-printcert', '-jarfile', self.apkFilePath]
            logging.debug(f"Running keytool command: {' '.join(cmd)}")

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
            q = queue.Queue()

            def enqueue_output(out, q):
                for line in iter(out.readline, ''):
                    q.put(line)
                out.close()

            t = threading.Thread(target=enqueue_output, args=(proc.stdout, q))
            t.daemon = True
            t.start()

            output_lines = []
            while True:
                try:
                    line = q.get(timeout=1)
                except queue.Empty:
                    if proc.poll() is not None:
                        break
                else:
                    output_lines.append(line)
                    if self.logs:
                        logging.info(f"[keytool output] {line.strip()}")

            proc.wait()
            output = ''.join(output_lines)
            logging.debug("Keytool process completed")

            certDetails = ""
            match = re.search('Owner: (.*)', output)
            if match:
                tempstr = '/' + '/'.join(match.group(1).split(", ")[::-1])
                certDetails = "SUBJECT: " + tempstr + "\n"
            else:
                certDetails = "Owner: CERT_ERROR\n"
            match = re.search('Issuer: (.*)', output)
            if match:
                tempstr = '/' + '/'.join(match.group(1).split(", ")[::-1])
                certDetails += "ISSUER: " + tempstr + "\n"
            else:
                certDetails += "Issuer: CERT_ERROR\n"
            match = re.search('SHA1: (.*)', output)
            if match:
                certDetails += "SHA1:" + match.group(1).replace(':', '').lower() + "\n"
            else:
                certDetails += "Certificate SHA1 : CERT_ERROR\n"
            match = re.search('MD5: (.*)', output)
            if match:
                certDetails += "MD5:" + match.group(1).replace(':', '').lower() + "\n"
            else:
                certDetails += "Certificate MD5 : CERT_ERROR\n"
            match = re.search('SHA256: (.*)', output)
            if match:
                certDetails += "SHA256:" + match.group(1).replace(':', '').lower() + "\n"
            else:
                certDetails += "Certificate SHA256 : CERT_ERROR\n"

            return certDetails.encode(encoding="UTF-8")

        except Exception as e:
            logging.error("Exception in get_cert_details", exc_info=True)
            return b"Certificate details unavailable\n"

    def create_apk_dump_file(self):
        self.apkFileName = os.path.basename(self.apkFilePath)
        logging.info(f"Creating dump for: {self.apkFileName}")

        self.fire_apk_tool(self.tempDir)

        self.allFilesList = getAllFilesList(self.tempDir)
        self.apkDumpFilesList = getDumpFilesList(self.tempDir, extensions=['.dex',
                                                                           'AndroidManifest.xml',
                                                                           'res' + os.sep + 'values' + os.sep + 'strings.xml',
                                                                           'res' + os.sep + 'values' + os.sep + 'public.xml'], )

        certDetails = self.get_cert_details()

        logging.info(f"Creating Dump file: {self.apkDumpPath}")

        with open(self.apkDumpPath, 'wb') as outfile:
            outfile.write(certDetails)
            for md5 in self.md5List:
                outfile.write(str(md5 + '\n').encode(encoding="UTF-8"))
            for fname in self.allFilesList:
                fpath = self.tempDir + os.sep + fname
                fileInfo = 'filename:%s filetype: unknown\n' % (fname.replace('\\', '/'))
                if self.logs:
                    logging.info(fileInfo.strip())
                outfile.write(fileInfo.encode("UTF-8"))
                if fname in self.apkDumpFilesList:
                    with open(fpath, 'rb') as infile:
                        outfile.write(infile.read())

    def process_file(self,bin_dir):
        logging.info(f"Processing file: {self.apkFilePath}")
        with open(self.apkFilePath, 'rb') as f:
            data = f.read()
        apk_md5 = hashlib.md5(data).hexdigest()
        self.apkDumpPath = os.path.join(bin_dir,apk_md5)+ '_apk_dump.bin'
        if self.forceDump or not os.path.exists(self.apkDumpPath):
            self.tempDir = tempfile.mkdtemp(prefix='apk_extract_')
            try:
                self.create_apk_dump_file()
            finally:
                shutil.rmtree(self.tempDir)

def getAllFilesList(dir):
    logging.debug(f"Gathering all files from: {dir}")
    files = []
    for root, dirnames, filenames in os.walk(dir):
        for filename in filenames:
            filename = os.path.join(root, filename)
            filename = filename.replace(dir, '')
            filename = filename.replace(os.sep, '', 1)
            files.append(filename)
    return files

def getDumpFilesList(dir, extensions=None):
    logging.debug("Filtering dump file list")
    files = []
    for root, dirnames, filenames in os.walk(dir):
        for filename in filenames:
            filepath = os.path.join(root, filename)
            filename_rel = filepath.replace(dir, '')
            filename_rel = filename_rel.replace(os.sep, '', 1)
            if extensions is None or filename_rel in extensions or filename_rel.endswith(tuple(extensions)):
                files.append(filename_rel)
            if filename_rel.startswith('original' + os.sep + 'META-INF') and (
                    filename_rel.endswith('.MF') or filename_rel.endswith('.SF')):
                files.append(filename_rel)
    if 'original{}AndroidManifest.xml'.format(os.sep) in files:
        files.remove('original{}AndroidManifest.xml'.format(os.sep))
    return files

def exist_file(x):
    if not os.path.exists(x):
        raise argparse.ArgumentTypeError("{0} does not exist".format(x))
    return x

def dump_apk(apkFile):
    logging.info("Starting APK dump process")

    if apkFile:
        apk_dir = os.path.dirname(apkFile)
        bin_dir = os.path.join(apk_dir, "bin")
        print(apk_dir,bin_dir)
        if not os.path.exists(bin_dir):
            os.makedirs(bin_dir)
        apkDump = ApkDump()
        apkDump.apkFilePath = apkFile
        apkDump.forceDump = "-f"
        apkDump.process_file(bin_dir)

def dump_individual_apk(apkFile):
    logging.info("Starting APK dump process")

    if apkFile:
        apk_dir = os.path.dirname(apkFile)
        apk_name = os.path.basename(apkFile)
        bin_dir = os.path.join(apk_dir, f"bin_{apk_name}")
        print(apk_dir,bin_dir)
        if not os.path.exists(bin_dir):
            os.makedirs(bin_dir)
        apkDump = ApkDump()
        apkDump.apkFilePath = apkFile
        apkDump.forceDump = "-f"
        apkDump.process_file(bin_dir)

def dump_apk_file(apk_file):
    try:
        if os.path.isfile(apk_file):
            dump_apk(full_path)
    except Exception as e:
                print(f"[ERROR] Failed to process {filename}: {e}")

def dump_all_apk_files(apk_folder):
    """
    Reads all files from the given folder and passes each file to dump_apk().
    """
    if not os.path.isdir(apk_folder):
        print(f"[ERROR] The folder '{apk_folder}' does not exist.")
        return

    for filename in os.listdir(apk_folder):
        full_path = os.path.join(apk_folder, filename)
        dump_apk_file(full_path)

# dump_apk("D:\\LLM\\zllama\\samples_for_testing\\sms\\1b5f84d5c562d3fd20dd8d7d3baeb343ef510ad1afb99dfda4c12cf8dca73e30.apk")
# folder = sys.argv[1]
# dump_all_apk_files(folder)
