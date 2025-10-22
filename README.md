# Downmix-Injector
Downmix Injector converts multichannel audio in video files into stereo AAC and injects it into new MKVs without re-encoding video. It scans folders, lists files missing stereo for selective batch processing, shows per-file and overall progress with ETA, and supports threaded ffmpeg and mkvmerge

A small Python GUI tool that scans a folder for video files missing a stereo audio track, downmixes the primary audio to stereo with ffmpeg, and muxes the new stereo AAC into a new MKV alongside the original streams using mkvmerge. Built for batch workflows, with per-file and overall progress, selectable files, bitrate presets, thread control, and optional cleanup.

Features
- Scan a folder and list video files that do not contain a 2 channel audio track
- Select individual files or Select All for processing
- Downmix first audio track to stereo AAC using ffmpeg with configurable threads
- Mux stereo track into a new MKV preserving original video and surround audio using mkvmerge
- Per-file progress bar updated from ffmpeg stderr and overall progress bar for the batch
- Dynamic ETA that updates as processing completes
- Bitrate presets and custom bitrate option (192k 256k 320k or custom)
- Option to delete the original video after successful mux
- Error logging to a file and user-facing messages in the GUI
- Lightweight, single-file script ready to copy/paste and run

Requirements
- Python 3.7 or newer
- ffmpeg and ffprobe accessible in PATH or placed in one of the common fallback locations used by the script
- mkvmerge from MKVToolNix accessible in PATH or placed in one of the common fallback locations used by the script
- Optional Python dependency: none required for the shipped script beyond the Python standard library

Installation
- Install Python if not already installed
- Download from https://www.python.org and add Python to PATH during install
- Install ffmpeg and ffprobe
- Easiest via Chocolatey on Windows:
- choco install ffmpeg
- Or download a Windows build and add the bin folder to PATH
- Install MKVToolNix
- Download from https://mkvtoolnix.download and install
- Ensure mkvmerge.exe is on PATH or note its full path
- Optional
- If you prefer the script to find tools by full path, edit the COMMON_FALLBACKS block at the top of the script and add the absolute paths you use

Usage
- Save the script to a file, for example stereo_injector.py
- From a terminal run:
- python stereo_injector.py
- In the GUI
- Browse to a folder containing video files
- Click Scan for files without stereo to populate the checklist
- Use Select All or Deselect All or pick individual files
- Choose a stereo bitrate preset or Custom and type a value like 320k
- Set FFmpeg threads or leave the auto-detected default
- Optionally check Delete original after mux
- Click Start Selected to begin processing
- Monitor per-file progress, overall progress, status messages, and ETA

Configuration
Settings are persisted in stereo_injector_config.json created in the script directory. The GUI exposes:
- delete_original_after_mux boolean
- ffmpeg_threads integer
- stereo_bitrate string such as 320k
For custom tool locations edit the COMMON_FALLBACKS dictionary near the top of the script to point to the exact executable paths for ffmpeg ffprobe and mkvmerge.

Troubleshooting
- Tool not found error
- Open a new Command Prompt and run:
- ffmpeg -version
- ffprobe -version
- mkvmerge -version
- If any command fails, add the executable folder to the Windows PATH or add its full path into COMMON_FALLBACKS and restart the script
- PATH changes not recognized
- After editing system PATH restart File Explorer or open a new terminal window before launching the script
- Progress is stuck at 0 or ETA reads N A
- Some inputs do not provide duration to ffprobe; the script falls back to sensible defaults and refines ETA as files process
- Check the error log file stereo_injector_errors.log for ffmpeg or mkvmerge errors
- Output file not created
- Check the log file for ffmpeg or mkvmerge error details
- Check that the input file is readable and that you have write permission in the folder

Notes and Recommendations
- Audio downmixing is CPU efficient and ffmpeg threading is exposed so you can tune thread count for your system
- The tool preserves the original streams; the new MKV is created with the original surround track retained and the new stereo track added and set as default
- The script deletes intermediate AAC files automatically and can optionally delete original video files after a successful mux
- For large batches, run on a machine with ample I/O and CPU cores; consider running during idle hours
