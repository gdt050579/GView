#include "JOB.hpp"

using namespace GView::Type::JOB;
using namespace GView::Type::JOB::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Information::Information(Reference<Object> _object, Reference<GView::Type::JOB::JOBFile> _job) : TabPage("Informa&tion")
{
    job     = _job;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });
    AddDecAndHexElement("Size", "%-20s (%s)", job->obj->GetData().GetSize());

    general->AddItem("Fixed Data Section").SetType(ListViewItem::Type::Category);

    const auto& productVersionName = JOB::ProductVersionNames.at(job->fixedLengthData.productVersion);
    const auto productVersionHex   = nf2.ToString((uint16) job->fixedLengthData.productVersion, hex);
    general->AddItem({ "Product Version", ls.Format("%-20s (%s)", productVersionName.data(), productVersionHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);
    AddDecAndHexElement("File Version", "%-20s (%s)", job->fixedLengthData.fileVersion);
    AddGUIDElement(general, "Job UUID", job->fixedLengthData.jobUUID);
    AddDecAndHexElement("App Name Len Offset", "%-20s (%s)", job->fixedLengthData.appNameLenOffset);
    AddDecAndHexElement("Trigger Offset", "%-20s (%s)", job->fixedLengthData.triggerOffset);
    AddDecAndHexElement("Error Retry Count", "%-20s (%s)", job->fixedLengthData.errorRetryCount);
    AddDecAndHexElement("Error Retry Interval", "%-20s (%s)", job->fixedLengthData.errorRetryInterval);
    AddDecAndHexElement("Idle Deadline", "%-20s (%s)", job->fixedLengthData.idleDeadline);
    AddDecAndHexElement("Idle Wait", "%-20s (%s)", job->fixedLengthData.idleWait);

    AddDecAndHexElement("Priority", "%-20s (%s)", job->fixedLengthData.priority.value);

    const auto& priority = job->fixedLengthData.priority;
    if (priority.fields.R)
    {
        general->AddItem({ "", "REALTIME" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (priority.fields.H)
    {
        general->AddItem({ "", "HIGH" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (priority.fields.I)
    {
        general->AddItem({ "", "IDLE" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (priority.fields.N)
    {
        general->AddItem({ "", "NORMAL" }).SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDecAndHexElement("Maximum Run Time", "%-20s (%s)", job->fixedLengthData.maximumRunTime);
    AddDecAndHexElement("Exit Code", "%-20s (%s)", job->fixedLengthData.exitCode);

    const auto& statusName      = JOB::StatusNames.at(job->fixedLengthData.status);
    const auto statusVersionHex = nf2.ToString((uint16) job->fixedLengthData.status, hex);
    general->AddItem({ "Status", ls.Format("%-20s (%s)", statusName.data(), statusVersionHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Flags", "%-20s (%s)", job->fixedLengthData.flags.value);

    const auto& flags = job->fixedLengthData.flags;
    if (flags.fields.I)
    {
        general->AddItem({ "", "INTERACTIVE" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.DD)
    {
        general->AddItem({ "", "DELETE_WHEN_DONE" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.D)
    {
        general->AddItem({ "", "DISABLED" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.SI)
    {
        general->AddItem({ "", "START_ONLY_IF_IDLE" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.KI)
    {
        general->AddItem({ "", "KILL_ON_IDLE_END" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.SB)
    {
        general->AddItem({ "", "DONT_START_IF_ON_BATTERIES" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.KB)
    {
        general->AddItem({ "", "KILL_IF_GOING_ON_BATTERIES" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.RD)
    {
        general->AddItem({ "", "RUN_ONLY_IF_DOCKED" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.H)
    {
        general->AddItem({ "", "HIDDEN" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.RC)
    {
        general->AddItem({ "", "RUN_IF_CONNECTED_TO_INTERNET" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.RI)
    {
        general->AddItem({ "", "RESTART_ON_IDLE_RESUME" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.SR)
    {
        general->AddItem({ "", "SYSTEM_REQUIRED" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.RL)
    {
        general->AddItem({ "", "RUN_ONLY_IF_LOGGED_ON" }).SetType(ListViewItem::Type::Emphasized_2);
    }
    if (flags.fields.AN)
    {
        general->AddItem({ "", "APPLICATION_NAME" }).SetType(ListViewItem::Type::Emphasized_2);
    }

    const auto& systemTime = job->fixedLengthData.systemTime;
    AddDecAndHexElement("System Time Low", "%-20s (%s)", systemTime.value.low);
    AddDecAndHexElement("System Time High", "%-20s (%s)", systemTime.value.high);

    const auto& fields = systemTime.fields;
    ls.Format(
          "%04d-%02d-%02d %02d:%02d:%02d:%04d",
          fields.year,
          fields.month,
          fields.day,
          fields.hour,
          fields.minute,
          fields.second,
          fields.milliSecond);

    general->AddItem({ "System Time Readable", ls.GetText() }).SetType(ListViewItem::Type::Emphasized_2);

    general->AddItem("Variable Size Data Section").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Running Instance Count", "%-20s (%s)", job->variableSizeDataSection.runningInstanceCount);
    general->AddItem({ "Application Name",
                       std::u16string_view{ (char16*) job->variableSizeDataSection.applicationName.GetData(), job->applicationNameSize } });
    general->AddItem(
          { "Parameters", std::u16string_view{ (char16*) job->variableSizeDataSection.parameters.GetData(), job->parametersSize } });
    general->AddItem(
          { "Working Directory",
            std::u16string_view{ (char16*) job->variableSizeDataSection.workingDirectory.GetData(), job->workingDirectorySize } });
    general->AddItem({ "Author", std::u16string_view{ (char16*) job->variableSizeDataSection.author.GetData(), job->authorSize } });
    general->AddItem({ "Comment", std::u16string_view{ (char16*) job->variableSizeDataSection.comment.GetData(), job->commentSize } });
    AddDecAndHexElement("User Data Size", "%-20s (%s)", (uint32) job->variableSizeDataSection.userData.GetLength());
    AddDecAndHexElement("Reserved Data Size", "%-20s (%s)", job->variableSizeDataSection.reservedData.size);
    if (job->variableSizeDataSection.reservedData.size > 0)
    {
        AddDecAndHexElement("Start Error", "%-20s (%s)", job->variableSizeDataSection.reservedData.taskReserved1.startError);
        AddDecAndHexElement("Task Flags", "%-20s (%s)", job->variableSizeDataSection.reservedData.taskReserved1.taskFlags);
    }
    AddDecAndHexElement("Triggers Count", "%-20s (%s)", job->variableSizeDataSection.triggers.count)
          .SetColor(ColorPair{ Color::Pink, Color::Transparent });
    if (job->variableSizeDataSection.triggers.count > 0)
    {
        for (const auto& trigger : job->variableSizeDataSection.triggers.items)
        {
            UpdateTrigger(trigger);
        }
    }

    if (job->variableSizeDataSection.jobSignature.has_value())
    {
        AddDecAndHexElement("Signature: Size", "%-20s (%s)", job->variableSizeDataSection.jobSignature->size);
        AddDecAndHexElement(
              "Signature: Minimum Client Version", "%-20s (%s)", job->variableSizeDataSection.jobSignature->minimumClientVersion);
    }
}

void Information::UpdateTrigger(const JOB::Trigger& trigger)
{
    AddDecAndHexElement("Trigger: Size", "%-20s (%s)", trigger.size);
    AddDecAndHexElement("Trigger: Reserved1", "%-20s (%s)", trigger.reserved1);
    AddDecAndHexElement("Trigger: Begin Year", "%-20s (%s)", trigger.beginYear);
    AddDecAndHexElement("Trigger: Begin Month", "%-20s (%s)", trigger.beginMonth);
    AddDecAndHexElement("Trigger: Begin Day", "%-20s (%s)", trigger.beginDay);
    AddDecAndHexElement("Trigger: End Year", "%-20s (%s)", trigger.endYear);
    AddDecAndHexElement("Trigger: End Month", "%-20s (%s)", trigger.endMonth);
    AddDecAndHexElement("Trigger: End Day", "%-20s (%s)", trigger.endDay);
    AddDecAndHexElement("Trigger: Start Hour", "%-20s (%s)", trigger.startHour);
    AddDecAndHexElement("Trigger: Start Minute", "%-20s (%s)", trigger.startMinute);
    AddDecAndHexElement("Trigger: Minutes Duration", "%-20s (%s)", trigger.minutesDuration);
    AddDecAndHexElement("Trigger: Minutes Interval", "%-20s (%s)", trigger.minutesInterval);
    AddDecAndHexElement("Trigger: Flags", "%-20s (%s)", trigger.flags.value);

    LocalString<1024> ls;
    NumericFormatter nf;
    const auto& typeName = JOB::TriggerTypeNames.at(trigger.type);
    const auto typeHex   = nf.ToString((uint32) trigger.type, hex);
    general->AddItem({ "Trigger: Type", ls.Format("%-20s (%s)", typeName.data(), typeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    if (trigger.type == TriggerType::DAILY) // did not see anything else but daily up until now
    {
        const Daily daily{ trigger.specific0 };
        AddDecAndHexElement("Trigger: Days Interval", "%-20s (%s)", daily.daysInterval).SetType(ListViewItem::Type::Emphasized_2);
    }
    else
    {
        AddDecAndHexElement("Trigger: Specific0", "%-20s (%s)", trigger.specific0);
    }
    AddDecAndHexElement("Trigger: Specific1", "%-20s (%s)", trigger.specific1);
    AddDecAndHexElement("Trigger: Specific2", "%-20s (%s)", trigger.specific2);
    AddDecAndHexElement("Trigger: Padding", "%-20s (%s)", trigger.padding);
    AddDecAndHexElement("Trigger: Reserved2", "%-20s (%s)", trigger.reserved2);
    AddDecAndHexElement("Trigger: Reserved3", "%-20s (%s)", trigger.reserved3);
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), std::min<>(this->GetHeight(), (int) general->GetItemsCount() + 3));

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

bool Information::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool Information::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        default:
            break;
        }
    }

    return false;
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
