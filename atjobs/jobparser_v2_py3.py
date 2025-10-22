#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python 3 port of the original jobparserkm.py
Original Author: Gleeda <jamie.levy@gmail.com>
Code fixes to jobparser.py by: Beercow
Additions by: Keven Murphy
Version: 2.0
"""

import sys
import os
import getopt
import struct
import codecs

# --- constants / lookup tables ------------------------------------------------

products = {
    0x400: "Windows NT 4.0",
    0x500: "Windows 2000",
    0x501: "Windows XP",
    0x600: "Windows Vista",
    0x601: "Windows 7",
    0x602: "Windows 8",
    0x603: "Windows 8.1",
    0xa00: "Windows 10",
}

task_status = {
    0x41300: "Task is ready to run",
    0x41301: "Task is running",
    0x41302: "Task is disabled",
    0x41303: "Task has not run",
    0x41304: "No more scheduled runs",
    0x41305: "Properties not set",
    0x41306: "Last run terminated by user",
    0x41307: "No triggers/triggers disabled",
    0x41308: "Triggers do not have set run times",
}

weekdays = {
    0x0: "Sunday",
    0x1: "Monday",
    0x2: "Tuesday",
    0x3: "Wednesday",
    0x4: "Thursday",
    0x5: "Friday",
    0x6: "Saturday",
}

months = {
    0x1: "Jan",
    0x2: "Feb",
    0x3: "Mar",
    0x4: "Apr",
    0x5: "May",
    0x6: "Jun",
    0x7: "Jul",
    0x8: "Aug",
    0x9: "Sep",
    0xa: "Oct",
    0xb: "Nov",
    0xc: "Dec",
}

flags = {
    0x1: "TASK_APPLICATION_NAME",
    0x200000: "TASK_FLAG_RUN_ONLY_IF_LOGGED_ON",
    0x100000: "TASK_FLAG_SYSTEM_REQUIRED",
    0x80000: "TASK_FLAG_RESTART_ON_IDLE_RESUME",
    0x40000: "TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET",
    0x20000: "TASK_FLAG_HIDDEN",
    0x10000: "TASK_FLAG_RUN_ONLY_IF_DOCKED",
    0x80000000: "TASK_FLAG_KILL_IF_GOING_ON_BATTERIES",
    0x40000000: "TASK_FLAG_DONT_START_IF_ON_BATTERIES",
    0x20000000: "TASK_FLAG_KILL_ON_IDLE_END",
    0x10000000: "TASK_FLAG_START_ONLY_IF_IDLE",
    0x4000000: "TASK_FLAG_DISABLED",
    0x2000000: "TASK_FLAG_DELETE_WHEN_DONE",
    0x1000000: "TASK_FLAG_INTERACTIVE",
}

triggerflags = {
    0x01: "TASK_TRIGGER_FLAG_HAS_END_DATE",
    0x02: "TASK_TRIGGER_FLAG_KILL_AT_DURATION_END",
    0x04: "TASK_TRIGGER_FLAG_DISABLED",
}

priorities = {
    0x20000000: "NORMAL_PRIORITY_CLASS",
    0x40000000: "IDLE_PRIORITY_CLASS",
    0x80000000: "HIGH_PRIORITY_CLASS",
    0x100000: "REALTIME_PRIORITY_CLASS",
}

triggertype = {
    0x00000000: "ONCE",
    0x00000001: "DAILY",
    0x00000002: "WEEKLY",
    0x00000003: "MONTHLYDATE",
    0x00000004: "MONTHLYDOW",
    0x00000005: "EVENT_ON_IDLE",
    0x00000006: "EVENT_AT_SYSTEMSTART",
    0x00000007: "EVENT_AT_LOGON",
}

exitcode = {
    0x0: "S_OK",
    0x1: "S_FALSE",
    0x80000002: "E_OUTOFMEMORY",
    0x80000009: "E_ACCESSDENIED",
    0x80000003: "E_INVALIDARG",
    0x80000008: "E_FAIL",
    0x8000FFFF: "E_UNEXPECTED",
    0x00041300: "SCHED_S_TASK_READY",
    0x00041301: "SCHED_S_TASK_RUNNING",
    0x00041302: "SCHED_S_TASK_DISABLED",
    0x00041303: "SCHED_S_TASK_HAS_NOT_RUN",
    0x00041304: "SCHED_S_TASK_NO_MORE_RUNS",
    0x00041305: "SCHED_S_TASK_NOT_SCHEDULED",
    0x00041306: "SCHED_S_TASK_TERMINATED",
    0x00041307: "SCHED_S_TASK_NO_VALID_TRIGGERS",
    0x00041308: "SCHED_S_EVENT_TRIGGER",
    0x80041309: "SCHED_E_TRIGGER_NOT_FOUND",
    0x8004130A: "SCHED_E_TASK_NOT_READY",
    0x8004130B: "SCHED_E_TASK_NOT_RUNNING",
    0x8004130C: "SCHED_E_SERVICE_NOT_INSTALLED",
    0x8004130D: "SCHED_E_CANNOT_OPEN_TASK",
    0x8004130E: "SCHED_E_INVALID_TASK",
    0x8004130F: "SCHED_E_ACCOUNT_INFORMATION_NOT_SET",
    0x80041310: "SCHED_E_ACCOUNT_NAME_NOT_FOUND",
    0x80041311: "SCHED_E_ACCOUNT_DBASE_CORRUPT",
    0x80041312: "SCHED_E_NO_SECURITY_SERVICES",
    0x80041313: "SCHED_E_UNKNOWN_OBJECT_VERSION",
    0x80041314: "SCHED_E_UNSUPPORTED_ACCOUNT_OPTION",
    0x80041315: "SCHED_E_SERVICE_NOT_RUNNING",
    0x80041316: "SCHED_E_UNEXPECTEDNODE",
    0x80041317: "SCHED_E_NAMESPACE",
    0x80041318: "SCHED_E_INVALIDVALUE",
    0x80041319: "SCHED_E_MISSINGNODE",
    0x8004131A: "SCHED_E_MALFORMEDXML",
    0x0004131B: "SCHED_S_SOME_TRIGGERS_FAILED",
    0x0004131C: "SCHED_S_BATCH_LOGON_PROBLEM",
    0x8004131D: "SCHED_E_TOO_MANY_NODES",
    0x8004131E: "SCHED_E_PAST_END_BOUNDARY",
    0x8004131F: "SCHED_E_ALREADY_RUNNING",
    0x80041320: "SCHED_E_USER_NOT_LOGGED_ON",
    0x80041321: "SCHED_E_INVALID_TASK_HASH",
    0x80041322: "SCHED_E_SERVICE_NOT_AVAILABLE",
    0x80041323: "SCHED_E_SERVICE_TOO_BUSY",
    0x80041324: "SCHED_E_TASK_ATTEMPTED",
    0x00041325: "SCHED_S_TASK_QUEUED",
    0x80041326: "SCHED_E_TASK_DISABLED",
    0x80041327: "SCHED_E_TASK_NOT_V1_COMPAT",
    0x80041328: "SCHED_E_START_ON_DEMAND",
}

# --- helper classes -----------------------------------------------------------

class JobDate:
    def __init__(self, data: bytes, scheduled=False):
        self.scheduled = scheduled
        self.Year = struct.unpack("<H", data[0:2])[0] if len(data) >= 2 else 0
        self.Month = struct.unpack("<H", data[2:4])[0] if len(data) >= 4 else 0

        if not self.scheduled:
            if len(data) >= 16:
                self.Weekday = struct.unpack("<H", data[4:6])[0]
                self.Day = struct.unpack("<H", data[6:8])[0]
                self.Hour = struct.unpack("<H", data[8:10])[0]
                self.Minute = struct.unpack("<H", data[10:12])[0]
                self.Second = struct.unpack("<H", data[12:14])[0]
                self.Milliseconds = struct.unpack("<H", data[14:16])[0]
            else:
                self.Weekday = None
                self.Day = self.Hour = self.Minute = self.Second = self.Milliseconds = 0
        else:
            self.Weekday = None
            self.Day = struct.unpack("<H", data[4:6])[0] if len(data) >= 6 else 0
            self.Hour = self.Minute = self.Second = self.Milliseconds = 0

    def __repr__(self):
        day = weekdays.get(self.Weekday, None)
        mon = months.get(self.Month, None)
        if day is not None and mon is not None and not self.scheduled:
            return "{0} {1} {2} {3:02}:{4:02}:{5:02}.{6} {7}".format(
                day, mon, self.Day, self.Hour, self.Minute, self.Second, self.Milliseconds, self.Year
            )
        elif self.scheduled and mon is None:
            return "Does not expire"
        elif self.scheduled:
            return "{0} {1} {2:02}:{3:02}:{4:02}.{5} {6}".format(
                mon, self.Day, self.Hour, self.Minute, self.Second, self.Milliseconds, self.Year
            )
        return "Task not yet run"

class UUID:
    def __init__(self, data: bytes):
        self.UUID0 = struct.unpack("<I", data[0:4])[0] if len(data) >= 4 else 0
        self.UUID1 = struct.unpack("<H", data[4:6])[0] if len(data) >= 6 else 0
        self.UUID2 = struct.unpack("<H", data[6:8])[0] if len(data) >= 8 else 0
        self.UUID3 = struct.unpack(">H", data[8:10])[0] if len(data) >= 10 else 0
        self.UUID4 = struct.unpack(">H", data[10:12])[0] if len(data) >= 12 else 0
        self.UUID5 = struct.unpack(">H", data[12:14])[0] if len(data) >= 14 else 0
        self.UUID6 = struct.unpack(">H", data[14:16])[0] if len(data) >= 16 else 0

    def __repr__(self):
        return "{" + "{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:02X}{5:02X}{6:02X}".format(
            self.UUID0, self.UUID1, self.UUID2, self.UUID3, self.UUID4, self.UUID5, self.UUID6
        ) + "}"

class TriggerFields:
    def __init__(self, data: bytes, ttype: int):
        self.ttype = ttype
        # initialize defaults
        self.DaysInterval = None
        self.WeeksInterval = None
        self.DaysOfTheWeek = None
        self.Days = None
        self.Months = None
        self.WhichWeek = None

        if self.ttype == 1:
            if len(data) >= 2:
                self.DaysInterval = struct.unpack("<H", data[0:2])[0]
        elif self.ttype == 2:
            if len(data) >= 4:
                self.WeeksInterval = struct.unpack("<H", data[0:2])[0]
                self.DaysOfTheWeek = struct.unpack("<H", data[2:4])[0]
        elif self.ttype == 3:
            if len(data) >= 6:
                self.Days = struct.unpack("<I", data[0:4])[0]
                self.Months = struct.unpack("<H", data[4:6])[0]
        elif self.ttype == 4:
            if len(data) >= 6:
                self.WhichWeek = struct.unpack("<H", data[0:2])[0]
                self.DaysOfTheWeek = struct.unpack("<H", data[2:4])[0]
                self.Months = struct.unpack("<H", data[4:6])[0]

    def __repr__(self):
        if self.ttype == 1:
            return "Days Interval: {0}\n".format(self.DaysInterval)
        elif self.ttype == 2:
            return "Weeks Interval: {0}\nDays Of The Week: {1}\n".format(self.WeeksInterval, self.DaysOfTheWeek)
        elif self.ttype == 3:
            return "Days: {0}\nMonths: {1}\n".format(self.Days, self.Months)
        elif self.ttype == 4:
            return "Which Week: {0}\nDays Of The Week: {1}\nMonths: {2}\n".format(
                self.WhichWeek, self.DaysOfTheWeek, self.Months
            )
        return ""

# --- Job class ---------------------------------------------------------------

class Job:
    def __init__(self, data: bytes):
        # safe reads with length guards
        self.ProductInfo = struct.unpack("<H", data[0:2])[0] if len(data) >= 2 else 0
        self.FileVersion = struct.unpack("<H", data[2:4])[0] if len(data) >= 4 else 0
        self.UUID = UUID(data[4:20] + b'\x00' * max(0, 20 - len(data)))
        self.AppNameLenOffset = struct.unpack("<H", data[20:22])[0] if len(data) >= 22 else 0
        self.TriggerOffset = struct.unpack("<H", data[22:24])[0] if len(data) >= 24 else 0
        self.ErrorRetryCount = struct.unpack("<H", data[24:26])[0] if len(data) >= 26 else 0
        self.ErrorRetryInterval = struct.unpack("<H", data[26:28])[0] if len(data) >= 28 else 0
        self.IdleDeadline = struct.unpack("<H", data[28:30])[0] if len(data) >= 30 else 0
        self.IdleWait = struct.unpack("<H", data[30:32])[0] if len(data) >= 32 else 0
        self.Priority = struct.unpack(">I", data[32:36])[0] if len(data) >= 36 else 0
        self.MaxRunTime = struct.unpack("<i", data[36:40])[0] if len(data) >= 40 else 0
        self.ExitCode = struct.unpack("<I", data[40:44])[0] if len(data) >= 44 else 0
        self.Status = struct.unpack("<i", data[44:48])[0] if len(data) >= 48 else 0
        self.Flags = struct.unpack(">I", data[48:52])[0] if len(data) >= 52 else 0
        self.RunDate = JobDate(data[52:68]) if len(data) >= 68 else JobDate(b'\x00' * 16)

        # variable section parsing
        self.RunningInstanceCount = struct.unpack("<H", data[68:70])[0] if len(data) >= 70 else 0
        self.NameLength = struct.unpack("<H", data[70:72])[0] if len(data) >= 72 else 0

        self.cursor = 72 + (self.NameLength * 2)
        self.Name = "Unknown"
        if self.NameLength > 0 and len(data) >= 72 + (self.NameLength * 2):
            rawname = data[72:72 + (self.NameLength * 2)]
            try:
                self.Name = rawname.decode("utf-16le", errors="ignore").replace('\x00', "")
            except Exception:
                self.Name = rawname.decode("latin-1", errors="ignore").replace('\x00', "")

        self.ParameterSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.Parameter = ""
        if self.ParameterSize > 0 and len(data) >= self.cursor + (self.ParameterSize * 2):
            rawparam = data[self.cursor:self.cursor + (self.ParameterSize * 2)]
            try:
                self.Parameter = rawparam.decode("utf-16le", errors="ignore").replace('\x00', "")
            except Exception:
                self.Parameter = rawparam.decode("latin-1", errors="ignore").replace('\x00', "")
            self.cursor += (self.ParameterSize * 2)

        self.WorkingDirectorySize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.WorkingDirectory = "Working Directory not set"
        if self.WorkingDirectorySize > 0 and len(data) >= self.cursor + (self.WorkingDirectorySize * 2):
            rawwd = data[self.cursor:self.cursor + (self.WorkingDirectorySize * 2)]
            try:
                self.WorkingDirectory = rawwd.decode("utf-16le", errors="ignore").replace('\x00', "")
            except Exception:
                self.WorkingDirectory = rawwd.decode("latin-1", errors="ignore").replace('\x00', "")
            self.cursor += (self.WorkingDirectorySize * 2)

        self.UserSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.User = "User not set"
        if self.UserSize > 0 and len(data) >= self.cursor + (self.UserSize * 2):
            rawuser = data[self.cursor:self.cursor + (self.UserSize * 2)]
            try:
                self.User = rawuser.decode("utf-16le", errors="ignore").replace('\x00', "")
            except Exception:
                self.User = rawuser.decode("latin-1", errors="ignore").replace('\x00', "")
            self.cursor += (self.UserSize * 2)

        self.CommentSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.Comment = "Comment not set"
        if self.CommentSize > 0 and len(data) >= self.cursor + (self.CommentSize * 2):
            rawcomment = data[self.cursor:self.cursor + (self.CommentSize * 2)]
            try:
                self.Comment = rawcomment.decode("utf-16le", errors="ignore").replace('\x00', "")
            except Exception:
                self.Comment = rawcomment.decode("latin-1", errors="ignore").replace('\x00', "")
            self.cursor += (self.CommentSize * 2)

        self.UserDataSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        if self.UserDataSize > 0 and len(data) >= self.cursor + (self.UserDataSize * 2):
            rawud = data[self.cursor:self.cursor + (self.UserDataSize * 2)]
            try:
                self.UserData = rawud.decode("utf-16le", errors="ignore").replace('\x00', "")
            except Exception:
                self.UserData = rawud.decode("latin-1", errors="ignore").replace('\x00', "")
            self.cursor += (self.UserDataSize * 2)
        else:
            self.UserData = ""

        self.ReservedDataSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2

        self.StartError = struct.unpack("<i", data[self.cursor:self.cursor + 4])[0] if len(data) >= self.cursor + 4 else 0
        self.cursor += 4
        self.TaskFlags = struct.unpack("<i", data[self.cursor:self.cursor + 4])[0] if len(data) >= self.cursor + 4 else 0
        self.cursor += 4

        self.TriggerCount = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.TriggerSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.Reserved1 = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2

        self.ScheduledStart = JobDate(data[self.cursor:self.cursor + 6], scheduled=True)
        self.cursor += 6
        self.ScheduledEnd = JobDate(data[self.cursor:self.cursor + 6], scheduled=True)
        self.cursor += 6

        self.StartHour = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.StartMinute = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.MinutesDuration = struct.unpack("<i", data[self.cursor:self.cursor + 4])[0] if len(data) >= self.cursor + 4 else 0
        self.cursor += 4
        self.MinutesInterval = struct.unpack("<i", data[self.cursor:self.cursor + 4])[0] if len(data) >= self.cursor + 4 else 0
        self.cursor += 4
        self.TriggerFlag = struct.unpack("<i", data[self.cursor:self.cursor + 4])[0] if len(data) >= self.cursor + 4 else 0
        self.cursor += 4
        self.TriggerType = struct.unpack("<i", data[self.cursor:self.cursor + 4])[0] if len(data) >= self.cursor + 4 else 0
        self.cursor += 4

        t_data = data[self.cursor:self.cursor + 6]
        if len(t_data) < 6:
            t_data = t_data + b'\x00' * (6 - len(t_data))
        self.TriggerSpecific = TriggerFields(t_data, self.TriggerType)
        self.cursor += 6

        self.Padding = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.Reserved2 = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2
        self.Reserved3 = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0] if len(data) >= self.cursor + 2 else 0
        self.cursor += 2

        self.Test = data[self.cursor:self.cursor + 2] if len(data) >= self.cursor + 2 else b''
        if self.Test != b'' and self.TriggerCount == 1 and len(data) >= self.cursor + 2:
            try:
                self.SignatureVersion = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
            except Exception:
                self.SignatureVersion = 0
            self.cursor += 2
            try:
                self.MinClientVersion = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
            except Exception:
                self.MinClientVersion = 0
            self.cursor += 2
            self.JobSignature = data[self.cursor:self.cursor + 64] if len(data) >= self.cursor + 64 else data[self.cursor:]
            self.cursor += 64
        else:
            self.JobSignature = b""

    def _get_job_info(self):
        lines = []
        lines.append("Product Info: {0}".format(products.get(self.ProductInfo, "Unknown Version")))
        lines.append("File Version: {0}".format(self.FileVersion))
        lines.append("UUID: {0}".format(self.UUID))
        lines.append("Error Retry Count: {0}".format(self.ErrorRetryCount))
        lines.append("Error Retry Interval: {0}".format(self.ErrorRetryInterval))
        lines.append("Idle Deadline: {0}".format(self.IdleDeadline))
        lines.append("Idle Wait: {0}".format(self.IdleWait))

        priority = ""
        for p in priorities:
            if self.Priority & p == p:
                priority += priorities[p] + ", "
        if priority != "":
            lines.append("Priorities: {0}".format(priority.rstrip(", ")))

        # ---- Corrected Maximum Run Time formatting ----
        try:
            hours, remainder = divmod(self.MaxRunTime, 3600000)
            minutes, remainder = divmod(remainder, 60000)
            seconds, milliseconds = divmod(remainder, 1000)
            lines.append("Maximum Run Time: {0:02}:{1:02}:{2:02}.{3} (HH:MM:SS.MS)".format(hours, minutes, seconds, milliseconds))
        except Exception:
            lines.append("Maximum Run Time: Unknown")

        ecode = ""
        for e in exitcode:
            if self.ExitCode == e:
                ecode = exitcode[e]
        lines.append("Exit Code: {0}".format(ecode))
        lines.append("Status: {0}".format(task_status.get(self.Status, "Unknown Status")))

        theflags = ""
        for flag in flags:
            if self.Flags & flag == flag:
                theflags += flags[flag] + ", "
        lines.append("Flags: {0}".format(theflags.rstrip(", ")))
        lines.append("Date Run: {0}".format(self.RunDate))
        lines.append("Running Instances: {0}".format(self.RunningInstanceCount))
        lines.append("Application: {0}".format(self.Name))
        if getattr(self, "Parameter", "") != "":
            lines.append("Parameters: {0}".format(self.Parameter))
        lines.append("Working Directory: {0}".format(self.WorkingDirectory))
        lines.append("User: {0}".format(self.User))
        lines.append("Comment: {0}".format(self.Comment))

        serror = ""
        for e in exitcode:
            if self.StartError == e:
                serror = exitcode[e]
        lines.append("Start Error: {0}".format(serror))
        lines.append("Trigger Count: {0}".format(self.TriggerCount))
        lines.append("Scheduled Start Date: {0}".format(self.ScheduledStart))
        lines.append("Scheduled End Date: {0}".format(self.ScheduledEnd))
        lines.append("Start Hour: {0}".format(self.StartHour))
        lines.append("Start Minute: {0}".format(self.StartMinute))
        lines.append("Minutes Duration: {0}".format(self.MinutesDuration))
        lines.append("Minutes Interval: {0}".format(self.MinutesInterval))

        tflags = ""
        for flag in triggerflags:
            if self.TriggerFlag & flag == flag:
                tflags += triggerflags[flag] + ","
        lines.append("Trigger Flags: {0}".format(tflags.rstrip(",")))

        ttype = ""
        for typ in triggertype:
            if self.TriggerType & typ == typ:
                ttype += triggertype[typ] + ","
        lines.append("Trigger Type: {0}\n".format(ttype.rstrip(",")))

        if self.TriggerSpecific != "":
            lines.append("{0}".format(self.TriggerSpecific))

        if hasattr(self, "JobSignature") and self.JobSignature:
            hex_str = "".join("{:02x}".format(b) for b in self.JobSignature)
            lines.append("Job Signature: {0}".format(hex_str))

        return lines

    def __repr__(self):
        lines = ""
        lines += "Product Info: {0}\n".format(products.get(self.ProductInfo, "None"))
        lines += "File Version: {0}\n".format(self.FileVersion)
        lines += "UUID: {0}\n".format(self.UUID)
        lines += "Error Retry Count: {0}\n".format(self.ErrorRetryCount)
        lines += "Error Retry Interval: {0}\n".format(self.ErrorRetryInterval)
        lines += "Idle Deadline: {0}\n".format(self.IdleDeadline)
        lines += "Idle Wait: {0}\n".format(self.IdleWait)

        priority = ""
        for p in priorities:
            if self.Priority & p == p:
                priority += priorities[p] + ", "
        if priority != "":
            lines += "Priorities: {0}\n".format(priority.rstrip(", "))

        # ---- Corrected Maximum Run Time formatting ----
        try:
            hours, remainder = divmod(self.MaxRunTime, 3600000)
            minutes, remainder = divmod(remainder, 60000)
            seconds, milliseconds = divmod(remainder, 1000)
            lines += "Maximum Run Time: {0:02}:{1:02}:{2:02}.{3} (HH:MM:SS.MS)\n".format(hours, minutes, seconds, milliseconds)
        except Exception:
            lines += "Maximum Run Time: Unknown\n"

        ecode = ""
        for e in exitcode:
            if self.ExitCode == e:
                ecode = exitcode[e]
        lines += "Exit Code: {0}\n".format(ecode)
        lines += "Status: {0}\n".format(task_status.get(self.Status, "Unknown Status"))

        theflags = ""
        for flag in flags:
            if self.Flags & flag == flag:
                theflags += flags[flag] + ", "
        lines += "Flags: {0}\n".format(theflags.rstrip(", "))
        lines += "Date Run: {0}\n".format(self.RunDate)
        lines += "Running Instances: {0}\n".format(self.RunningInstanceCount)
        lines += "Application: {0}\n".format(self.Name)
        if getattr(self, "Parameter", "") != "":
            lines += "Parameters: {0}\n".format(self.Parameter)
        lines += "Working Directory: {0}\n".format(self.WorkingDirectory)
        lines += "User: {0}\n".format(self.User)
        lines += "Comment: {0}\n".format(self.Comment)

        serror = ""
        for e in exitcode:
            if self.StartError == e:
                serror = exitcode[e]
        lines += "Start Error: {0}\n".format(serror)
        lines += "Trigger Count: {0}\n".format(self.TriggerCount)
        lines += "Scheduled Start Date: {0}\n".format(self.ScheduledStart)
        lines += "Scheduled End Date: {0}\n".format(self.ScheduledEnd)
        lines += "Start Hour: {0}\n".format(self.StartHour)
        lines += "Start Minute: {0}\n".format(self.StartMinute)
        lines += "Minutes Duration: {0}\n".format(self.MinutesDuration)
        lines += "Minutes Interval: {0}\n".format(self.MinutesInterval)

        tflags = ""
        for flag in triggerflags:
            if self.TriggerFlag & flag == flag:
                tflags += triggerflags[flag] + ","
        lines += "Trigger Flags: {0}\n".format(tflags.rstrip(","))

        ttype = ""
        for typ in triggertype:
            if self.TriggerType & typ == typ:
                ttype = triggertype[typ]
        lines += "Trigger Type: {0}\n".format(ttype)

        if self.TriggerSpecific != "":
            lines += "{0}".format(self.TriggerSpecific)

        if hasattr(self, "JobSignature") and self.JobSignature:
            hex_str = "".join("{:02x}".format(b) for b in self.JobSignature)
            lines += "Job Signature: {0}\n".format(hex_str)
        return lines

# --- CLI / Main --------------------------------------------------------------

def usage():
    print("jobparserkm_py3.py:\n")
    print(" -f <job>")
    print(" -d <directory of job files>")
    print(" -o <output file>")
    print(" -s <summary file>")
    print(" -h help")

def main():
    file_arg = None
    dir_arg = None
    output_file = None
    summary_file = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:d:o:s:", ["help", "file=", "dir=", "output=", "summary="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            print("\nAdditional options:")
            print("  -o, --output   Specify output text file for full details")
            print("  -s, --summary  Specify summary text file (pipe-delimited App|Params|UUID|Source File)")
            sys.exit(0)
        elif o in ("-f", "--file"):
            if os.path.isfile(a):
                file_arg = a
            else:
                print(a + " is not a file")
                usage()
                return
        elif o in ("-d", "--dir"):
            dir_arg = a
        elif o in ("-o", "--output"):
            output_file = a
        elif o in ("-s", "--summary"):
            summary_file = a
        else:
            assert False, "unhandled option\n\n"
            sys.exit(2)

    if not output_file:
        output_file = "jobparser_output.txt"
    if not summary_file:
        summary_file = "jobparser_summary.txt"

    if file_arg is None and dir_arg is None:
        usage()
        return

    with codecs.open(output_file, "a", "utf-8") as out, codecs.open(summary_file, "a", "utf-8") as summary:
        try:
            if os.path.getsize(summary_file) == 0:
                #summary.write("File|UUID|Application|Parameters\n")
                summary.write("Application|Parameters|UUID|File\n")
        except Exception:
            #summary.write("File|UUID|Application|Parameters\n")
            summary.write("Application|Parameters|UUID|File\n")


        def process_job(job: Job, filename: str):
            print("*" * 72)
            print("File:", filename)
            print(job)
            print("*" * 72)

            out.write("*" * 72 + "\n")
            out.write("File: " + filename + "\n")
            out.write(str(job) + "\n")
            out.write("*" * 72 + "\n")

            uuid = str(job.UUID)
            app = getattr(job, "Name", "").replace("|", " ")
            params = getattr(job, "Parameter", "").replace("|", " ")
            summary.write("{}|{}|{}|{}\n".format(
               app.replace("|", " "),
               params.replace("|", " "),
               uuid.replace("|", " "),
               filename.replace("|", " ")
               #app.replace("|", " "),
               #params.replace("|", " ")
            ))

        if dir_arg and os.path.isdir(dir_arg):
            for fname in os.listdir(dir_arg):
                if fname.endswith(".job") and os.path.isfile(os.path.join(dir_arg, fname)):
                    path = os.path.join(dir_arg, fname)
                    try:
                        with open(path, "rb") as f:
                            job = Job(f.read(0x2000))
                            process_job(job, path)
                    except Exception as e:
                        print("Unable to process file: {} ({})".format(path, e))
        elif file_arg:
            try:
                with open(file_arg, "rb") as f:
                    job = Job(f.read(0x2000))
                    process_job(job, file_arg)
            except Exception as e:
                print("Unable to process file: {} ({})".format(file_arg, e))

if __name__ == "__main__":
    main()

