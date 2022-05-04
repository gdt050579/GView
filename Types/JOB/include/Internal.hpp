#pragma once

#include <GView.hpp>

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/96446df7-7683-40e0-a713-b01933b93b18

namespace GView::Type::JOB
{
#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

#pragma pack(push, 1)
struct MyGUID
{
    uint32 a;
    uint16 b;
    uint16 c;
    uint8 d[8];

    bool operator==(const MyGUID& other) const
    {
        return memcmp(this, &other, sizeof(MyGUID)) == 0;
    }
};
#pragma pack(pop)

static_assert(sizeof(MyGUID) == 16);

/*
    Fixed-length section
    The fixed-length section is 68 bytes in size and consists of:

    offset size value	description
    0	   2		    Product version
    2	   2	1	    File (format) version
    4	   16		    Job UUID (or GUID)
    20	   2		    Application name size offset. The offset is relative from the start of the file.
    22	   2		    Trigger offset. The offset is relative from the start of the file.
    24	   2		    Error Retry Count
    26	   2		    Error Retry Interval
    28	   2		    Idle Deadline
    30	   2		    Idle Wait
    32	   4		    Priority
    36	   4		    Maximum Run Time
    40	   4		    Exit Code
    44	   4		    Status
    48	   4		    Flags
    52	   16		    Last run time. Consists of a SYSTEMTIME
*/

enum class ProductVersion : uint16
{
    WindowsNT4Point0 = 0x0400,
    Windows2000      = 0x0500,
    WindowsXP        = 0x0501,
    WindowsVista     = 0x0600,
    Windows7         = 0x0601,
    Windows8         = 0x0602,
    Windows8Point1   = 0x0603,
    Windows10        = 0x0a00,
};

static const std::map<ProductVersion, std::string_view> ProductVersionNames{
    GET_PAIR_FROM_ENUM(ProductVersion::WindowsNT4Point0), GET_PAIR_FROM_ENUM(ProductVersion::Windows2000),
    GET_PAIR_FROM_ENUM(ProductVersion::WindowsXP),        GET_PAIR_FROM_ENUM(ProductVersion::WindowsVista),
    GET_PAIR_FROM_ENUM(ProductVersion::Windows7),         GET_PAIR_FROM_ENUM(ProductVersion::Windows8),
    GET_PAIR_FROM_ENUM(ProductVersion::Windows8Point1),   GET_PAIR_FROM_ENUM(ProductVersion::Windows10)
};

union Priority
{
    struct
    {
        uint8 : 5;
        uint8 N : 1; // If set to 1, the task can run at the highest possible priority. The threads of a real-time priority class process
                     // preempt the threads of all other processes, including operating system processes performing important tasks.
        uint8 I : 1; // If set to 1, the task performs time-critical tasks that can be executed immediately for it to run correctly. The
                     // threads of a high-priority class process preempt the threads of normal or idle priority class processes.
        uint8 H : 1; // If set to 1, the task can run in a process whose threads run only when the machine is idle, and are preempted by the
                     // threads of any process running in a higher priority class.
        uint8 R : 1; // If set to 1, the task can run at the highest possible priority. The threads of a real-time priority class
                     // process preempt the threads of all other processes, including operating system processes performing important tasks.
        uint8 : 7;
        uint8 : 8;
        uint8 : 8;
    } fields;
    uint32 value;
};

static_assert(sizeof(Priority) == 4);

enum class Status : uint32
{
    SCHED_S_TASK_READY         = 0x00041300, // Task is not running but is scheduled to run at some time in the future.
    SCHED_S_TASK_RUNNING       = 0x00041301, // Task is currently running.
    SCHED_S_TASK_NOT_SCHEDULED = 0x00041305, // The task is not running and has no valid triggers.
};

static const std::map<Status, std::string_view> StatusNames{ GET_PAIR_FROM_ENUM(Status::SCHED_S_TASK_READY),
                                                             GET_PAIR_FROM_ENUM(Status::SCHED_S_TASK_RUNNING),
                                                             GET_PAIR_FROM_ENUM(Status::SCHED_S_TASK_NOT_SCHEDULED) };

union Flags
{
    struct
    {
        uint8 I : 1;  // TASK_FLAG_INTERACTIVE -> If set to 1, specifies that the task can interact with the logged-on user.
        uint8 DD : 1; // TASK_FLAG_DELETE_WHEN_DONE -> If set to 1, specifies that the task can be deleted when there are no more scheduled
                      // run times.
        uint8 D : 1;  // TASK_FLAG_DISABLED -> If set to 1, specifies that the task is disabled.
        uint8 : 1;
        uint8 SI : 1; // TASK_FLAG_START_ONLY_IF_IDLE -> If set to 1, specifies that the task begins only if the computer is not in use at
                      // the scheduled time.
        uint8 KI : 1; // TASK_FLAG_KILL_ON_IDLE_END -> If set to 1, specifies that the task can be terminated if the computer makes an idle
                      // to non-idle transition while the task is running. The computer makes an idle to non-idle transition when user input
                      // is detected.
        uint8 SB : 1; // TASK_FLAG_DONT_START_IF_ON_BATTERIES -> If set to 1, specifies that the task cannot start if its target computer is
                      // running on battery power.
        uint8 KB : 1; // TASK_FLAG_KILL_IF_GOING_ON_BATTERIES -> If set to 1, specifies that the task can end, and the associated
                      // application quit if the task's target computer switches to battery power.
        uint8 RD : 1; // TASK_FLAG_RUN_ONLY_IF_DOCKED -> Unused. MUST be set to zero when sent and MUST be ignored on receipt.
        uint8 H : 1;  // TASK_FLAG_HIDDEN -> If set to 1, specifies that the task is hidden.
        uint8 RC : 1; // TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET -> Unused. MUST be set to zero when sent and MUST be ignored on receipt.
        uint8 RI : 1; // TASK_FLAG_RESTART_ON_IDLE_RESUME -> If set to 1, specifies that the task can start again if the computer makes a
                      // non-idle to idle transition before all the task's triggers elapse.
        uint8 SR : 1; // TASK_FLAG_SYSTEM_REQUIRED -> If set to 1, specifies that the task can cause the system to resume, or awaken if the
                      // system is sleeping.
        uint8 RL : 1; // TASK_FLAG_RUN_ONLY_IF_LOGGED_ON -> If set to 1, specifies that the task can only run if the user specified in the
                      // task is logged on interactively.
        uint8 : 2;
        uint8 : 8;
        uint8 AN : 1; // TASK_APPLICATION_NAME -> If set to 1, specifies that the task has an application name defined.
        uint8 : 7;
    } fields;

    uint32 value;
};

static_assert(sizeof(Flags) == 4);

union SystemTime
{
    struct
    {
        uint16 year;
        uint16 month;
        uint16 weekday;
        uint16 day;
        uint16 hour;
        uint16 minute;
        uint16 second;
        uint16 milliSecond;
    } fields;
    struct
    {
        uint64 low;
        uint64 high;
    } value;
};

static_assert(sizeof(SystemTime) == 16);

#pragma pack(push, 1)
struct FIXDLEN_DATA
{
    ProductVersion productVersion;
    uint16 fileVersion; // 0x0001
    MyGUID jobUUID;
    uint16 appNameLenOffset;   // The offset is relative from the start of the file.
    uint16 triggerOffset;      // The offset is relative from the start of the file.
    uint16 errorRetryCount;    // Contains the number of execute attempts that are attempted for the task if the task fails to start.
    uint16 errorRetryInterval; // Contains the interval, in minutes, between successive retries.
    uint16 idleDeadline;       // Contains a maximum time in minutes to wait for the machine to become idle for Idle Wait minutes.
    uint16 idleWait;           // Contains a value in minutes. The machine remains idle for this many minutes before it runs the task.
    Priority priority;         // Contains ONE of the bit flags that control the priority at which the task will run.
    uint32 maximumRunTime;     // Contains the number of milliseconds the server will wait for the task to complete.
    uint32 exitCode; // This contains the exit code of the executed task upon the completion of that task. MUST be set to 0x00000000
                     // when sent and MUST be ignored on receipt.
    Status status;   // This contains the current status of the task. Is to be set to 0 and ignored upon receipt.
    Flags flags;
    SystemTime systemTime;
};
#pragma pack(pop)

static_assert(sizeof(FIXDLEN_DATA) == 68);

} // namespace GView::Type::JOB
