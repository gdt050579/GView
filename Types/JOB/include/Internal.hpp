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
    TASK_READY         = 0x00041300, // Task is not running but is scheduled to run at some time in the future.
    TASK_RUNNING       = 0x00041301, // Task is currently running.
    TASK_NOT_SCHEDULED = 0x00041305, // The task is not running and has no valid triggers.
};

static const std::map<Status, std::string_view> StatusNames{ GET_PAIR_FROM_ENUM(Status::TASK_READY),
                                                             GET_PAIR_FROM_ENUM(Status::TASK_RUNNING),
                                                             GET_PAIR_FROM_ENUM(Status::TASK_NOT_SCHEDULED) };

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

enum class VariableSizeDataSectionMembers : uint32
{
    RunningInstanceCount = 0,
    ApplicationName      = 1, // -> Consists of a Unicode string.
    Parameters           = 2, // -> Consists of a Unicode string.
    WorkingDirectory     = 3, // -> Consists of a Unicode string.
    Author               = 4, // -> Consists of a Unicode string.
    Comment              = 5, // -> Consists of a Unicode string.
    UserData             = 6,
    ReservedData         = 7,
    Triggers             = 8,
    JobSignature         = 9,
};

struct TASKRESERVED1
{
    uint32 startError;
    uint32 taskFlags;
};

struct ReservedData
{
    uint16 size;
    TASKRESERVED1 taskReserved1;
};

/*
    Trigger
    offset size value description
    0	   2		  Trigger Size
    2	   2		  Reserved1
    4	   2		  Begin Year
    6	   2		  Begin Month
    8	   2		  Begin Day
    10	   2		  End Year
    12	   2		  End Month
    14	   2		  End Day
    16	   2		  Start Hour
    18	   2		  Start Minute
    20	   4		  Minutes Duration
    24	   4		  Minutes Interval
    28	   4		  Flags
    32	   4		  Trigger Type
    36	   2		  TriggerSpecific0
    38	   2		  TriggerSpecific1
    40	   2		  TriggerSpecific2
    42	   2		  Padding
    44	   2		  Reserved2
    46	   2		  Reserved3
*/

union TriggerFlags
{
    struct
    {
        uint8 E : 1; // TASK_TRIGGER_FLAG_HAS_END_DATE         -> If set to 1, specifies that the task can stop at some point in time.
        uint8 K : 1; // TASK_TRIGGER_FLAG_KILL_AT_DURATION_END -> If set to 1, specifies that the task can be stopped at the end of the
                     // repetition period.
        uint8 D : 1; // TASK_TRIGGER_FLAG_DISABLED             -> If set to 1, specifies that the trigger is disabled.
        uint8 : 5;
        uint8 : 8;
        uint8 : 8;
    } fields;
    uint32 value;
};

enum class TriggerType : uint32
{
    ONCE                 = 0x00000000,
    DAILY                = 0x00000001,
    WEEKLY               = 0x00000002,
    MONTHLYDATE          = 0x00000003,
    MONTHLYDOW           = 0x00000004,
    EVENT_ON_IDLE        = 0x00000005,
    EVENT_AT_SYSTEMSTART = 0x00000006,
    EVENT_AT_LOGON       = 0x00000007,
};

static const std::map<TriggerType, std::string_view> TriggerTypeNames{ GET_PAIR_FROM_ENUM(TriggerType::ONCE),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::DAILY),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::WEEKLY),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::MONTHLYDATE),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::MONTHLYDOW),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::EVENT_ON_IDLE),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::EVENT_AT_SYSTEMSTART),
                                                                       GET_PAIR_FROM_ENUM(TriggerType::EVENT_AT_LOGON) };

union DayOfTheMonth
{
    struct
    {
        uint8 X : 1;
        uint8 A : 1;
        uint8 B : 1;
        uint8 C : 1;
        uint8 D : 1;
        uint8 E : 1;
        uint8 F : 1;
        uint8 G : 1;
        uint8 H : 1;
        uint8 I : 1;
        uint8 J : 1;
        uint8 K : 1;
        uint8 L : 1;
        uint8 M : 1;
        uint8 N : 1;
        uint8 O : 1;
        uint8 P : 1;
        uint8 Q : 1;
        uint8 R : 1;
        uint8 S : 1;
        uint8 T : 1;
        uint8 U : 1;
        uint8 V : 1;
        uint8 _9 : 1;
        uint8 _8 : 1;
        uint8 _7 : 1;
        uint8 _6 : 1;
        uint8 _5 : 1;
        uint8 _4 : 1;
        uint8 _3 : 1;
        uint8 _2 : 1;
        uint8 _1 : 1;
    } fields;

    struct
    {
        uint16 specific0;
        uint16 specific1;
    } value;
};

union DayOfTheWeek
{
    struct
    {
        uint8 SU : 1; // Sunday    -> If set to 1, specifies that the task can run on Sunday.
        uint8 MO : 1; // Monday    -> If set to 1, specifies that the task can run on Monday.
        uint8 TU : 1; // Tuesday   -> If set to 1, specifies that the task can run on Tuesday.
        uint8 WE : 1; // Wednesday -> If set to 1, specifies that the task can run on Wednesday.
        uint8 TH : 1; // Thursday  -> If set to 1, specifies that the task can run on Thursday.
        uint8 FR : 1; // Friday    -> If set to 1, specifies that the task can run on Friday.
        uint8 SA : 1; // Saturday  -> If set to 1, specifies that the task can run on Saturday.
        uint8 : 1;
        uint8 : 8;
    } fields;

    uint16 specific0;
};

union MonthOfTheYear
{
    struct
    {
        uint8 JA : 1; // January   -> If set to 1, specifies that the task can run on January.
        uint8 FE : 1; // February  -> If set to 1, specifies that the task can run on February.
        uint8 MR : 1; // March     -> If set to 1, specifies that the task can run on March.
        uint8 AP : 1; // April     -> If set to 1, specifies that the task can run on April.
        uint8 MA : 1; // May       -> If set to 1, specifies that the task can run on May.
        uint8 JU : 1; // June      -> If set to 1, specifies that the task can run on June.
        uint8 JL : 1; // July      -> If set to 1, specifies that the task can run on July.
        uint8 AU : 1; // August    -> If set to 1, specifies that the task can run on August.
        uint8 SE : 1; // September -> If set to 1, specifies that the task can run on September.
        uint8 OC : 1; // October   -> If set to 1, specifies that the task can run on October.
        uint8 NO : 1; // November  -> If set to 1, specifies that the task can run on November.
        uint8 DE : 1; // December  -> If set to 1, specifies that the task can run on December.
        uint8 : 4;
    } fields;

    uint16 specific0;
};

struct Daily
{
    uint16 daysInterval; // specific0 field
};

struct Weekly
{
    uint16 weeksInterval;
    DayOfTheWeek daysOfTheWeek;
};

struct MonthlyDate
{
    DayOfTheMonth days;
    MonthOfTheYear months;
};

enum class WhichWeek : uint16
{
    FIRST_WEEK  = 0x0001,
    SECOND_WEEK = 0x0002,
    THIRD_WEEK  = 0x0003,
    FOURTH_WEEK = 0x0004,
    LAST_WEEK   = 0x0005,
};

struct MonthlyDow // monthly day of week
{
    WhichWeek whichWeek;
    DayOfTheWeek daysOfTheWeek;
    MonthOfTheYear months;
};

struct Trigger
{
    uint16 size;       // Set to 0x0030. When creating a job, the value SHOULD be ignored upon receipt.
    uint16 reserved1;  // This field is ignored when read in from the file and is set to 0.
    uint16 beginYear;  // This field contains the first date this trigger is to fire. Begin Year SHOULD be in the range of 1601 to 30827.
    uint16 beginMonth; // This field contains the first date this trigger is to fire. Begin Month SHOULD be in the range of 1 to 12.
    uint16 beginDay;   // This field contains the first date this trigger fires. Begin Day SHOULD be in the range of 1 to the number of days
                       // in the month specified by the Begin Month field.
    uint16 endYear;    // These fields are ignored if the TASK_TRIGGER_FLAG_HAS_END_DATE bit is not set in the Flags field. Otherwise, these
                       // fields are set to the last date this trigger fires. End Year SHOULD be in the range of 1601 to 30827.
    uint16 endMonth;   // These fields are ignored if the TASK_TRIGGER_FLAG_HAS_END_DATE bit is not set in the Flags field. Otherwise, these
                       // fields are set to the last date this trigger is to fire. End Month SHOULD be in the range of 1 to 12.
    uint16 endDay;     // These fields are ignored if the TASK_TRIGGER_FLAG_HAS_END_DATE bit is not set in the Flags field. Otherwise, these
                   // fields are set to the last date this trigger is to fire. End Day SHOULD be in the range of 1 to the number of days in
                   // the month specified by the End Month field.
    uint16 startHour;   // This field is set to the hour of the day when this trigger fires. Start Hour is in the range 0 to 23.
    uint16 startMinute; // This field is set to the minute of the hour when this trigger is to fire. Start Minute is in the range 0 to 59.
    uint32 minutesDuration; // This field contains a value in minutes, in the range 0x00000000 to 0xFFFFFFFF. For example, if Minutes
                            // Duration is 60, and Minutes Interval is 15, then if started at 1:00, the task runs every 15 minutes for the
                            // next 60 minutes (five times: at 1:00, 1:15, 1:30, 1:45, and 2:00.)
    uint32 minutesInterval; // This field contains a value in minutes, in the range 0x00000000 to 0xFFFFFFFF. Minutes Interval indicates the
                            // time period between repeated trigger firings.
    TriggerFlags flags;     // This field contains zero or more bit flags.
    TriggerType type;
    uint16 specific0; // This field is set to values specific to each trigger type.
    uint16 specific1; // This field is set to values specific to each trigger type.
    uint16 specific2; // This field is set to values specific to each trigger type.
    uint16 padding;   // MUST be set to zero when sent and MUST be ignored on receipt.
    uint16 reserved2; // MUST be set to zero when sent and MUST be ignored on receipt.
    uint16 reserved3; // MUST be set to zero when sent and MUST be ignored on receipt.
};

struct Triggers
{
    uint16 count;
    std::vector<Trigger> items;
};

struct JobSignature
{
    uint16 size;
    uint16 minimumClientVersion;
    uint8 signature[64];
};

struct VariableSizeDataSection
{
    uint16 runningInstanceCount;
    Buffer applicationName;
    Buffer parameters;
    Buffer workingDirectory;
    Buffer author;
    Buffer comment;
    Buffer userData;
    ReservedData reservedData;
    Triggers triggers;
    std::optional<JobSignature> jobSignature;
};

} // namespace GView::Type::JOB
