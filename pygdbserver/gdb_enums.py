# coding=utf-8
"""
All enums required for the GDB server
"""
from enum import Enum

TargetWaitkind = Enum("TargetWaitkind",
                      ["EXITED", "STOPPED", "SIGNALLED", "LOADED", "FORKED", "VFORKED", "EXECD", "VFORK_DONE",
                       "SYSCALL_ENTRY", "SYSCALL_RETURN", "SPURIOUS", "IGNORE", "NO_HISTORY", "NO_RESUMED",
                       "THREAD_CREATED", "THREAD_EXITED"])

RegisterStatus = Enum("RegisterStatus", {"REG_UNKNOWN": 0, "REG_VALID": 1, "REG_UNAVAILABLE": -1})

ResumeKind = Enum("ResumeKind", ["RESUME_CONTINUE", "RESUME_STEP", "RESUME_STOP"])

TargetStopReason = Enum("TargetStopReason", ["TARGET_STOPPED_BY_NO_REASON", "TARGET_STOPPED_BY_SW_BREAKPOINT",
                                             "TARGET_STOPPED_BY_HW_BREAKPOINT", "TARGET_STOPPED_BY_WATCHPOINT",
                                             "TARGET_STOPPED_BY_SINGLE_STEP"])

BtraceFormat = Enum("BtraceFormat", ["BTRACE_FORMAT_NONE", "BTRACE_FORMAT_BTS", "BTRACE_FORMAT_PT"])

BkptType = Enum("BkptType", ["GDB_BREAKPOINT_Z0", "GDB_BREAKPOINT_Z1", "GDB_BREAKPOINT_Z2", "GDB_BREAKPOINT_Z3",
                             "GDB_BREAKPOINT_Z4", "SINGLE_STEP_BREAKPOINT", "OTHER_BREAKPOINT"])

RawBkptType = Enum("RawBkptType",
                   ["RAW_BKPT_TYPE_SW", "RAW_BKPT_TYPE_HW", "RAW_BKPT_TYPE_WRITE_WP", "RAW_BKPT_TYPE_READ_WP",
                    "RAW_BKPT_TYPE_ACCESS_WP"])
