#!/usr/bin/env python3
"""
Downmix Remuxer — full, fixed script
- Recursive scan option
- Selectable checklist, Select All / Deselect All
- Refresh durations
- Per-file progress from ffmpeg and mkvmerge (size-polled)
- Overall progress and ETA computed from elapsed time + progress fraction
- Robust executable detection with common Windows fallbacks
Requirements:
- Python 3.7+
- ffmpeg, ffprobe, mkvmerge in PATH or configured in COMMON_FALLBACKS
"""
import os
import json
import shutil
import subprocess
import threading
import time
import re
from pathlib import Path
from queue import Queue, Empty
from typing import Callable
import tkinter as tk
from tkinter import filedialog, ttk, messagebox

# ---------- CONFIG ----------
VIDEO_EXTENSIONS = [".mkv", ".mp4", ".mov", ".m4v"]
DEFAULT_STEREO_BITRATE = "320k"
LOG_FILE = "stereo_injector_errors.log"
CONFIG_FILE = "stereo_injector_config.json"
DEFAULT_THREADS = max(1, os.cpu_count() or 4)

# Edit fallbacks to point to your local installations if needed
COMMON_FALLBACKS = {
    "ffmpeg": [
        r"C:\ffmpeg\bin\ffmpeg.exe",
        r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
        r"C:\Program Files\FFmpeg\bin\ffmpeg.exe",
        r"C:\Program Files\Gyan\ffmpeg\bin\ffmpeg.exe",
    ],
    "ffprobe": [
        r"C:\ffmpeg\bin\ffprobe.exe",
        r"C:\Program Files\ffmpeg\bin\ffprobe.exe",
    ],
    "mkvmerge": [
        r"C:\Program Files\MKVToolNix\mkvmerge.exe",
        r"C:\Program Files (x86)\MKVToolNix\mkvmerge.exe",
    ]
}

# ---------- UTILITIES ----------
def log_error(message: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} {message}\n")
    except Exception:
        pass

def load_config():
    defaults = {
        "delete_original_after_mux": False,
        "ffmpeg_threads": DEFAULT_THREADS,
        "stereo_bitrate": DEFAULT_STEREO_BITRATE,
        "scan_subfolders": True
    }
    try:
        p = Path(CONFIG_FILE)
        if p.exists():
            cfg = json.loads(p.read_text(encoding="utf-8"))
            for k, v in defaults.items():
                cfg.setdefault(k, v)
            return cfg
    except Exception as e:
        log_error(f"[Config Load] {e}")
    return defaults.copy()

def save_config(cfg: dict):
    try:
        Path(CONFIG_FILE).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception as e:
        log_error(f"[Config Save] {e}")

def run_subprocess(cmd, timeout=None):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0:
            log_error(f"[Subprocess Error] {' '.join(cmd)}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired as e:
        log_error(f"[Subprocess Timeout] {' '.join(cmd)}: {e}")
        return False
    except Exception as e:
        log_error(f"[Subprocess Exception] {' '.join(cmd)}: {e}")
        return False

def find_executable(cmd_name: str, fallbacks=None):
    exe = shutil.which(cmd_name)
    if not exe and os.name == "nt":
        exe = shutil.which(cmd_name + ".exe")
    if exe:
        return exe
    if fallbacks:
        for p in fallbacks:
            if Path(p).exists():
                return p
    return None

# ---------- ffprobe / ffmpeg helpers ----------
def ffprobe_get_audio_channel_counts(ffprobe_cmd: str, file_path: Path):
    try:
        cmd = [
            ffprobe_cmd, "-v", "error",
            "-select_streams", "a",
            "-show_entries", "stream=channels",
            "-of", "default=noprint_wrappers=1:nokey=0",
            str(file_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return []
        counts = []
        for line in res.stdout.splitlines():
            if line.startswith("channels="):
                try:
                    counts.append(int(line.split("=", 1)[1].strip()))
                except Exception:
                    pass
        return counts
    except Exception as e:
        log_error(f"[ffprobe error] {file_path}: {e}")
        return []

def has_stereo_track(ffprobe_cmd: str, file_path: Path):
    return 2 in ffprobe_get_audio_channel_counts(ffprobe_cmd, file_path)

def ffprobe_get_duration(ffprobe_cmd: str, file_path: Path):
    try:
        cmd = [ffprobe_cmd, "-v", "error", "-show_entries", "format=duration",
               "-of", "default=noprint_wrappers=1:nokey=1", str(file_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return None
        s = res.stdout.strip()
        return float(s) if s else None
    except Exception as e:
        log_error(f"[ffprobe duration error] {file_path}: {e}")
        return None

_re_time = re.compile(r"time=(\d{2}):(\d{2}):(\d{2})\.(\d{2})")
def parse_ffmpeg_time(line: str):
    m = _re_time.search(line)
    if not m:
        return None
    hh, mm, ss, centi = map(int, m.groups())
    return hh * 3600 + mm * 60 + ss + centi / 100.0

def downmix_to_stereo_with_progress(ffmpeg_cmd: str, input_path: Path, output_path: Path, threads: int, bitrate: str, total_seconds: float, progress_callback: Callable[[float], None]):
    cmd = [
        ffmpeg_cmd, "-y",
        "-threads", str(threads),
        "-i", str(input_path),
        "-map", "0:a:0",
        "-ac", "2",
        "-c:a", "aac",
        "-b:a", bitrate,
        str(output_path)
    ]
    try:
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, bufsize=1)
    except Exception as e:
        log_error(f"[ffmpeg launch error] {' '.join(cmd)}: {e}")
        return False
    try:
        last_pct = 0.0
        while True:
            if proc.stderr is None:
                break
            line = proc.stderr.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            t = parse_ffmpeg_time(line)
            if t is not None and total_seconds and total_seconds > 0:
                pct = min(100.0, max(0.0, (t / total_seconds) * 100.0))
                if pct - last_pct >= 0.5:
                    last_pct = pct
                    progress_callback(pct)
        proc.wait()
        return proc.returncode == 0
    except Exception as e:
        log_error(f"[ffmpeg progress error] {e}")
        try:
            proc.kill()
        except Exception:
            pass
        return False

def mux_stereo_with_progress(mkvmerge_cmd: str, original_file: Path, stereo_aac: Path, output_file: Path, progress_callback: Callable[[float], None], poll_interval: float = 0.5, set_default_stereo: bool = True) -> bool:
    """
    Run mkvmerge and estimate progress by polling output file size vs expected size.
    Falls back to a running indicator if sizes unavailable.
    """
    cmd = [
        mkvmerge_cmd,
        "-o", str(output_file),
        str(original_file),
        str(stereo_aac),
        "--track-name", "0:Surround",
        "--track-name", "1:Stereo"
    ]
    if set_default_stereo:
        cmd += ["--default-track", "1:yes"]

    try:
        orig_size = original_file.stat().st_size
    except Exception:
        orig_size = 0
    try:
        stereo_size = stereo_aac.stat().st_size
    except Exception:
        stereo_size = 0
    expected = orig_size + stereo_size
    use_size_estimate = expected > 1024

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log_error(f"[mkvmerge launch error] {' '.join(cmd)}: {e}")
        return False

    last_report = 0.0
    try:
        while True:
            if proc.poll() is not None:
                break
            if output_file.exists() and use_size_estimate:
                try:
                    cur = output_file.stat().st_size
                    pct = min(100.0, max(0.0, (cur / expected) * 100.0))
                except Exception:
                    pct = last_report
            else:
                pct = min(99.0, last_report + 1.0)
            if pct - last_report >= 0.5:
                last_report = pct
                progress_callback(pct)
            time.sleep(poll_interval)
        proc.wait()
        if output_file.exists():
            progress_callback(100.0)
            return proc.returncode == 0
        else:
            return False
    except Exception as e:
        log_error(f"[mkvmerge progress error] {e}")
        try:
            proc.kill()
        except Exception:
            pass
        return False

# ---------- PROCESSING ----------
def process_single_file(file_path: Path, queue: Queue, cfg: dict, tools, timing_state: dict):
    ffmpeg_cmd, ffprobe_cmd, mkvmerge_cmd = tools
    queue.put(("log", f"Processing: {file_path.name}"))
    if has_stereo_track(ffprobe_cmd, file_path):
        queue.put(("skip", file_path.name))
        return

    stereo_path = file_path.with_name(f"{file_path.stem}_stereo.aac")
    output_path = file_path.with_name(f"{file_path.stem}_with_stereo.mkv")

    dur = timing_state.get('durations_map', {}).get(str(file_path), None)
    if dur is None:
        dur = ffprobe_get_duration(ffprobe_cmd, file_path) or 0.0

    queue.put(("status", f"Downmixing {file_path.name}"))
    start = time.time()

    def ff_cb(pct):
        queue.put(("file_progress", pct))

    ok = downmix_to_stereo_with_progress(
        ffmpeg_cmd, file_path, stereo_path,
        threads=cfg.get("ffmpeg_threads", DEFAULT_THREADS),
        bitrate=cfg.get("stereo_bitrate", DEFAULT_STEREO_BITRATE),
        total_seconds=dur,
        progress_callback=ff_cb
    )
    queue.put(("file_progress", 100.0))
    elapsed = time.time() - start

    media_seconds = dur if dur and dur > 0 else timing_state.get('nominal_sec_per_unknown', 60.0)
    timing_state['processed_media_seconds'] += media_seconds
    timing_state['processing_seconds'] += elapsed
    timing_state['files_done'] += 1

    if not ok or not stereo_path.exists():
        queue.put(("error", f"Downmix failed: {file_path.name}"))
        try:
            if stereo_path.exists():
                stereo_path.unlink()
        except Exception:
            pass
        return

    queue.put(("status", f"Muxing {file_path.name}"))

    def mux_cb(pct):
        queue.put(("file_progress", pct))

    ok = mux_stereo_with_progress(mkvmerge_cmd, file_path, stereo_path, output_path, progress_callback=mux_cb, poll_interval=0.5, set_default_stereo=True)
    if not ok or not output_path.exists():
        queue.put(("error", f"Mux failed: {file_path.name}"))
        try:
            if stereo_path.exists():
                stereo_path.unlink()
        except Exception:
            pass
        return

    try:
        if stereo_path.exists():
            stereo_path.unlink()
    except Exception as e:
        log_error(f"[Cleanup Error] {e}")

    if cfg.get("delete_original_after_mux", False):
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            log_error(f"[Cleanup Error - original] {e}")

    queue.put(("done", output_path.name))

def folder_worker_with_selection(folder: Path, selections: list, queue: Queue, cfg: dict, stop_event: threading.Event, tools, precomputed_durations_map=None):
    total = len(selections)
    queue.put(("info", f"Scheduled {total} files for processing"))
    queue.put(("total_files", total))

    durations_map = precomputed_durations_map.copy() if precomputed_durations_map else {}
    for p in selections:
        if stop_event.is_set():
            queue.put(("info", "Processing stopped by user"))
            return
        if str(p) not in durations_map:
            try:
                d = ffprobe_get_duration(tools[1], p) or 0.0
                durations_map[str(p)] = d
            except Exception as e:
                durations_map[str(p)] = 0.0
                log_error(f"[duration scan error] {p}: {e}")

    nominal = 60.0
    total_media_seconds = sum(d for d in durations_map.values() if d and d > 0)
    unknown_count = sum(1 for p in selections if not durations_map.get(str(p)))
    if total_media_seconds == 0.0 and unknown_count > 0:
        total_media_seconds = unknown_count * nominal

    timing_state = {
        'durations_map': durations_map,
        'total_media_seconds': total_media_seconds,
        'processed_media_seconds': 0.0,
        'processing_seconds': 0.0,
        'files_done': 0,
        'nominal_sec_per_unknown': nominal,
        'start_time': time.time()
    }

    processed = 0
    for p in selections:
        if stop_event.is_set():
            queue.put(("info", "Processing stopped by user"))
            break

        queue.put(("file_progress", 0.0))
        process_single_file(p, queue, cfg, tools, timing_state)
        processed += 1
        queue.put(("overall_progress", processed))

        remaining_media_seconds = max(0.0, timing_state['total_media_seconds'] - timing_state['processed_media_seconds'])

        if timing_state['processed_media_seconds'] > 0 and timing_state['processing_seconds'] > 0:
            rate = timing_state['processing_seconds'] / timing_state['processed_media_seconds']
            eta_seconds = rate * remaining_media_seconds
        else:
            avg_elapsed_per_file = (timing_state['processing_seconds'] / max(1, timing_state['files_done'])) if timing_state['files_done'] > 0 else 10.0
            eta_seconds = avg_elapsed_per_file * (total - processed)

        queue.put(("eta_update", eta_seconds))

    queue.put(("finished", "All done"))

# ---------- GUI ----------
class ScrollableCheckboxList(ttk.Frame):
    def __init__(self, master, items=None, **kwargs):
        super().__init__(master, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.frame = ttk.Frame(self.canvas)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.create_window((0, 0), window=self.frame, anchor="nw")
        self.frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.vars = []
        items = items or []
        for it in items:
            self.add_item(it)

    def add_item(self, text: str):
        var = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(self.frame, text=text, variable=var)
        cb.pack(anchor="w", padx=2, pady=1)
        self.vars.append((var, text))
        return var

    def clear(self):
        for child in self.frame.winfo_children():
            child.destroy()
        self.vars = []

    def get_checked(self):
        return [text for (var, text) in self.vars if var.get()]

    def set_all(self, value=True):
        for var, _ in self.vars:
            var.set(value)

class StereoInjectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Downmix Remuxer — Select Files")
        self.root.geometry("940x700")
        self.cfg = load_config()

        # resolve tools
        self.ffmpeg_res = find_executable("ffmpeg", COMMON_FALLBACKS.get("ffmpeg"))
        self.ffprobe_res = find_executable("ffprobe", COMMON_FALLBACKS.get("ffprobe"))
        self.mkvmerge_res = find_executable("mkvmerge", COMMON_FALLBACKS.get("mkvmerge"))
        self.tools = (self.ffmpeg_res, self.ffprobe_res, self.mkvmerge_res)

        # durations_map stores durations from last scan/refresh (keyed by full path string)
        self.durations_map = {}

        top = ttk.Frame(root); top.pack(fill="x", padx=10, pady=8)
        ttk.Label(top, text="Folder:").grid(row=0, column=0, sticky="w")
        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(top, textvariable=self.folder_var, width=86); self.folder_entry.grid(row=1, column=0, sticky="w")
        ttk.Button(top, text="Browse", command=self.browse_folder).grid(row=1, column=1, sticky="e")
        ttk.Button(top, text="Scan for files without stereo", command=self.scan_folder).grid(row=1, column=2, padx=(8,0))

        options = ttk.Frame(root); options.pack(fill="x", padx=10, pady=(6,8))
        self.delete_var = tk.BooleanVar(value=self.cfg.get("delete_original_after_mux", False))
        ttk.Checkbutton(options, text="Delete original after mux", variable=self.delete_var).grid(row=0, column=0, sticky="w")
        ttk.Label(options, text="FFmpeg threads:").grid(row=0, column=1, sticky="e", padx=(10,2))
        self.threads_var = tk.IntVar(value=self.cfg.get("ffmpeg_threads", DEFAULT_THREADS))
        ttk.Spinbox(options, from_=1, to=max(1, os.cpu_count() or 4)*2, textvariable=self.threads_var, width=6).grid(row=0, column=2, sticky="w")
        ttk.Label(options, text="Stereo bitrate:").grid(row=0, column=3, sticky="e", padx=(10,2))
        self.bitrate_presets = ["192k", "256k", "320k", "Custom..."]
        self.bitrate_combo = ttk.Combobox(options, values=self.bitrate_presets, state="readonly", width=12)
        if self.cfg.get("stereo_bitrate") in self.bitrate_presets:
            self.bitrate_combo.set(self.cfg.get("stereo_bitrate"))
        else:
            self.bitrate_combo.set("Custom...")
        self.bitrate_combo.grid(row=0, column=4, sticky="w")
        self.custom_bitrate_var = tk.StringVar(value=self.cfg.get("stereo_bitrate"))
        self.custom_bitrate_entry = ttk.Entry(options, textvariable=self.custom_bitrate_var, width=10)
        if self.bitrate_combo.get() == "Custom...":
            self.custom_bitrate_entry.grid(row=0, column=5, sticky="w", padx=(6,0))
        def on_bitrate_change(event=None):
            sel = self.bitrate_combo.get()
            if sel == "Custom...":
                self.custom_bitrate_entry.grid(row=0, column=5, sticky="w", padx=(6,0))
            else:
                self.custom_bitrate_entry.grid_forget()
                self.custom_bitrate_var.set(sel)
        self.bitrate_combo.bind("<<ComboboxSelected>>", on_bitrate_change)

        # Include subfolders option
        self.scan_subfolders_var = tk.BooleanVar(value=self.cfg.get("scan_subfolders", True))
        ttk.Checkbutton(options, text="Include subfolders in scan", variable=self.scan_subfolders_var).grid(row=0, column=6, sticky="w", padx=(10,0))

        # File checklist area
        list_frame = ttk.LabelFrame(root, text="Files without stereo (select to process)")
        list_frame.pack(fill="both", expand=False, padx=10, pady=(0,8))
        self.checklist = ScrollableCheckboxList(list_frame, items=[])
        self.checklist.pack(fill="both", expand=True, padx=6, pady=6)
        btn_frame = ttk.Frame(root); btn_frame.pack(fill="x", padx=10, pady=(0,8))
        ttk.Button(btn_frame, text="Select All", command=lambda: self.checklist.set_all(True)).pack(side="left")
        ttk.Button(btn_frame, text="Deselect All", command=lambda: self.checklist.set_all(False)).pack(side="left", padx=(6,0))
        ttk.Button(btn_frame, text="Refresh durations", command=self.refresh_selected_durations).pack(side="left", padx=(6,0))

        # Controls
        control_frame = ttk.Frame(root); control_frame.pack(fill="x", padx=10, pady=(0,8))
        self.start_btn = ttk.Button(control_frame, text="Start Selected", command=self.start_processing); self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_processing, state="disabled"); self.stop_btn.pack(side="left", padx=(6,0))
        self.status_label = ttk.Label(control_frame, text="Idle"); self.status_label.pack(side="right")

        # Progress
        prog_frame = ttk.Frame(root); prog_frame.pack(fill="x", padx=10, pady=(0,8))
        ttk.Label(prog_frame, text="Current file:").grid(row=0, column=0, sticky="w")
        self.file_progress = ttk.Progressbar(prog_frame, orient="horizontal", length=560, mode="determinate")
        self.file_progress.grid(row=0, column=1, padx=(6,0), sticky="w")
        self.file_progress_label = ttk.Label(prog_frame, text="0%"); self.file_progress_label.grid(row=0, column=2, padx=(8,0))
        ttk.Label(prog_frame, text="Overall:").grid(row=1, column=0, sticky="w", pady=(6,0))
        self.overall_progress = ttk.Progressbar(prog_frame, orient="horizontal", length=560, mode="determinate")
        self.overall_progress.grid(row=1, column=1, padx=(6,0), sticky="w", pady=(6,0))
        self.overall_progress_label = ttk.Label(prog_frame, text="0/0"); self.overall_progress_label.grid(row=1, column=2, padx=(8,0), pady=(6,0))
        self.eta_label = ttk.Label(prog_frame, text="ETA: N/A"); self.eta_label.grid(row=2, column=1, sticky="w", pady=(6,0))

        # Log area
        text_frame = ttk.Frame(root); text_frame.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self.log_text = tk.Text(text_frame, wrap="word", state="normal")
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("skip", foreground="green")
        scrollbar = ttk.Scrollbar(text_frame, command=self.log_text.yview); scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # worker state
        self.queue = Queue()
        self.worker_thread = None
        self.stop_event = threading.Event()
        self.total_files = 0
        self.processed_files = 0
        self.current_file_pct = 0.0
        self.process_start_time = None

        # periodic poll
        self.root.after(200, self.poll_queue)
        self.preflight()

    def preflight(self):
        missing = []
        if not self.ffmpeg_res:
            missing.append("ffmpeg")
        if not self.ffprobe_res:
            missing.append("ffprobe")
        if not self.mkvmerge_res:
            missing.append("mkvmerge")
        if missing:
            self.append_log(f"Missing tools: {', '.join(missing)}", "error")
            self.append_log("Edit COMMON_FALLBACKS in the script or ensure binaries are in PATH.", "error")
            messagebox.showwarning("Missing Tools", f"Required tools may be missing: {', '.join(missing)}")
            self.start_btn.config(state="disabled")
        else:
            self.append_log(f"Resolved executables: ffmpeg={self.ffmpeg_res}, ffprobe={self.ffprobe_res}, mkvmerge={self.mkvmerge_res}")

    def append_log(self, msg: str, tag=None):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n", (tag if tag else ""))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def browse_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def scan_folder(self):
        folder = self.folder_var.get().strip()
        if not folder:
            messagebox.showwarning("Select Folder", "Please select a folder to scan.")
            return
        folder_path = Path(folder)
        if not folder_path.exists() or not folder_path.is_dir():
            messagebox.showerror("Folder Error", "Selected folder is not valid.")
            return

        # persist scan_subfolders preference
        self.cfg['scan_subfolders'] = bool(self.scan_subfolders_var.get())
        save_config(self.cfg)

        self.checklist.clear()
        self.durations_map = {}
        self.append_log(f"Scanning folder: {folder_path} (recursive={self.scan_subfolders_var.get()})")

        if self.scan_subfolders_var.get():
            candidates = sorted([p for p in folder_path.rglob("*") if p.suffix.lower() in VIDEO_EXTENSIONS and p.is_file()])
        else:
            candidates = sorted([p for p in folder_path.iterdir() if p.suffix.lower() in VIDEO_EXTENSIONS and p.is_file()])

        missing_stereo = []
        for p in candidates:
            try:
                if not has_stereo_track(self.ffprobe_res, p):
                    missing_stereo.append(p)
            except Exception as e:
                log_error(f"[scan error] {p}: {e}")

        if not missing_stereo:
            self.append_log("No files without stereo found.")
            return

        for p in missing_stereo:
            self.checklist.add_item(str(p))
            try:
                d = ffprobe_get_duration(self.ffprobe_res, p) or 0.0
                if d and d > 0:
                    self.durations_map[str(p)] = d
            except Exception:
                pass

        self.checklist.set_all(True)
        self.append_log(f"Found {len(missing_stereo)} files without stereo; selected all by default.")
        if any(not self.durations_map.get(str(p)) for p in missing_stereo):
            self.append_log("Note: some files lack duration metadata. Use 'Refresh durations' for better ETA.")

    def refresh_selected_durations(self):
        checked = self.checklist.get_checked()
        if not checked:
            messagebox.showinfo("No selection", "No files selected.")
            return
        self.append_log("Refreshing durations for selected files...")
        for s in checked:
            p = Path(s)
            try:
                d = ffprobe_get_duration(self.ffprobe_res, p) or 0.0
                self.durations_map[str(p)] = d
                self.append_log(f"Duration: {p.name} -> {format_seconds(d) if d else 'unknown'}")
            except Exception as e:
                log_error(f"[refresh duration error] {p}: {e}")
                self.append_log(f"Duration: {p.name} -> unknown", "error")
        self.append_log("Durations refreshed. ETA will use updated values when processing starts.")

    def start_processing(self):
        checked = self.checklist.get_checked()
        if not checked:
            messagebox.showwarning("Select Files", "No files selected to process.")
            return
        selections = [Path(s) for s in checked]

        selected_preset = self.bitrate_combo.get()
        if selected_preset == "Custom...":
            bitrate = self.custom_bitrate_var.get().strip() or DEFAULT_STEREO_BITRATE
        else:
            bitrate = selected_preset or DEFAULT_STEREO_BITRATE

        self.cfg = {
            "delete_original_after_mux": bool(self.delete_var.get()),
            "ffmpeg_threads": int(self.threads_var.get()),
            "stereo_bitrate": bitrate,
            "scan_subfolders": bool(self.scan_subfolders_var.get())
        }
        save_config(self.cfg)

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Running")
        self.append_log(f"Starting processing of {len(selections)} files")

        self.total_files = len(selections)
        self.processed_files = 0
        self.current_file_pct = 0.0
        self.process_start_time = time.time()

        self.overall_progress['maximum'] = max(1, self.total_files)
        self.overall_progress['value'] = 0
        self.overall_progress_label.config(text=f"0/{self.total_files}")
        self.file_progress['value'] = 0
        self.file_progress_label.config(text="0%")
        self.eta_label.config(text="ETA: calculating...")

        self.stop_event.clear()
        self.worker_thread = threading.Thread(
            target=folder_worker_with_selection,
            args=(Path(self.folder_var.get()), selections, self.queue, self.cfg, self.stop_event, self.tools, self.durations_map),
            daemon=True
        )
        self.worker_thread.start()

    def stop_processing(self):
        if messagebox.askyesno("Stop", "Stop after current file finishes?"):
            self.stop_event.set()
            self.append_log("Stop requested; current file will finish then stop.")
            self.stop_btn.config(state="disabled")

    def compute_eta_from_elapsed(self):
        if not self.process_start_time or self.total_files <= 0:
            return None
        elapsed = time.time() - self.process_start_time
        overall_done = self.processed_files + (self.current_file_pct / 100.0)
        overall_frac = overall_done / self.total_files
        if overall_frac <= 0.0:
            return None
        remaining_factor = (1.0 / overall_frac) - 1.0
        eta_seconds = elapsed * remaining_factor
        return eta_seconds

    def poll_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if not item or not isinstance(item, tuple):
                    continue
                typ, msg = item[0], item[1]
                if typ == "info":
                    self.append_log(msg)
                elif typ == "status":
                    self.append_log(msg)
                    self.status_label.config(text=msg)
                    self.file_progress['value'] = 0
                    self.file_progress_label.config(text="0%")
                    self.current_file_pct = 0.0
                elif typ == "file_progress":
                    pct = float(msg)
                    self.file_progress['value'] = pct
                    self.file_progress_label.config(text=f"{pct:.0f}%")
                    self.current_file_pct = pct
                    eta = self.compute_eta_from_elapsed()
                    if eta is not None:
                        self.eta_label.config(text=f"ETA: {format_seconds(eta)}")
                    else:
                        self.eta_label.config(text="ETA: calculating...")
                elif typ == "overall_progress":
                    self.processed_files = int(msg)
                    self.overall_progress['value'] = self.processed_files
                    self.overall_progress_label.config(text=f"{self.processed_files}/{self.total_files}")
                    eta = self.compute_eta_from_elapsed()
                    if eta is not None:
                        self.eta_label.config(text=f"ETA: {format_seconds(eta)}")
                    else:
                        self.eta_label.config(text="ETA: calculating...")
                elif typ == "eta_update":
                    # kept for compatibility; ignored in favour of elapsed-based ETA
                    pass
                elif typ == "done":
                    self.append_log(f"Done: {msg}")
                elif typ == "skip":
                    self.append_log(f"Skipped (stereo exists): {msg}", "skip")
                    self.processed_files += 1
                    self.overall_progress['value'] = self.processed_files
                    self.overall_progress_label.config(text=f"{self.processed_files}/{self.total_files}")
                    eta = self.compute_eta_from_elapsed()
                    if eta is not None:
                        self.eta_label.config(text=f"ETA: {format_seconds(eta)}")
                elif typ == "error":
                    self.append_log(msg, "error")
                    self.processed_files += 1
                    self.overall_progress['value'] = self.processed_files
                    self.overall_progress_label.config(text=f"{self.processed_files}/{self.total_files}")
                    eta = self.compute_eta_from_elapsed()
                    if eta is not None:
                        self.eta_label.config(text=f"ETA: {format_seconds(eta)}")
                elif typ == "log":
                    self.append_log(msg)
                elif typ == "finished":
                    self.append_log(msg)
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.status_label.config(text="Idle")
                    self.file_progress['value'] = 100
                    self.file_progress_label.config(text="100%")
                    self.eta_label.config(text="ETA: done")
                else:
                    self.append_log(f"{typ}: {msg}")
        except Empty:
            pass
        finally:
            self.root.after(200, self.poll_queue)

def format_seconds(s):
    if s is None:
        return "N/A"
    try:
        s = int(round(s))
    except Exception:
        return "N/A"
    if s < 60:
        return f"{s}s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{m}m {sec}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"

def main():
    root = tk.Tk()
    app = StereoInjectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()