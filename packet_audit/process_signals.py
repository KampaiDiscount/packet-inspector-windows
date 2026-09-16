"""Keep Windows console interruption under the capture supervisor's control."""
import multiprocessing as mp
import os
import signal


def ignore_windows_child_interrupts() -> None:
    """Children drain queues on sentinels, not console-wide Ctrl+C/Ctrl+Break.

    Do not change POSIX handlers or handlers of an embedding main process.
    Failure to install a required child handler is a visible startup failure.
    """
    if os.name != 'nt' or mp.parent_process() is None:
        return
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGBREAK, signal.SIG_IGN)
