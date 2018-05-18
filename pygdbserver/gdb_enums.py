# coding=utf-8
"""
All enums required for the GDB server
"""
from enum import Enum

TargetWaitkind = Enum("TargetWaitkind",
                      ["TARGET_WAITKIND_EXITED", "TARGET_WAITKIND_STOPPED", "TARGET_WAITKIND_SIGNALLED",
                       "TARGET_WAITKIND_LOADED", "TARGET_WAITKIND_FORKED", "TARGET_WAITKIND_VFORKED",
                       "TARGET_WAITKIND_EXECD", "TARGET_WAITKIND_VFORK_DONE", "TARGET_WAITKIND_SYSCALL_ENTRY",
                       "TARGET_WAITKIND_SYSCALL_RETURN", "TARGET_WAITKIND_SPURIOUS", "TARGET_WAITKIND_IGNORE",
                       "TARGET_WAITKIND_NO_HISTORY", "TARGET_WAITKIND_NO_RESUMED", "TARGET_WAITKIND_THREAD_CREATED",
                       "TARGET_WAITKIND_THREAD_EXITED"])

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
