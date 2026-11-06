import { useEffect, useRef, useState } from 'react'
import { i18nT } from '../../i18n/t'
import { fmtWeekday } from '../../i18n/format'
import SimpleSelect from '../../components/SimpleSelect'
import ErrorNotice from '../../components/ErrorNotice'
import { errorText } from './errorText'
import { REPEATS, REPEAT_MINUTES, nextFireAt, scheduleOf, type Repeat, type Schedule } from './reminderSchedule'
import type { Reminder } from './types'

export type OnReschedule = (id: string, fireAt: string, everyMinutes: number | null) => Promise<unknown>

const REPEAT_LABEL: Record<Repeat, () => string> = {
  once: () => i18nT('apps.crewCompanion.reminders.schedule_once'),
  hourly: () => i18nT('apps.crewCompanion.reminders.schedule_hourly'),
  daily: () => i18nT('apps.crewCompanion.reminders.schedule_daily'),
  weekly: () => i18nT('apps.crewCompanion.reminders.schedule_weekly'),
}
/** ISO weekdays, Monday first. */
const WEEKDAYS = ['1', '2', '3', '4', '5', '6', '7']
const pad = (n: number) => String(n).padStart(2, '0')

/** A reminder row's Change schedule form: the same reminder, a hand-set repeat and time. */
export default function ReminderScheduleEditor({ r, onReschedule, onClose }: {
  r: Reminder
  onReschedule: OnReschedule
  /** After the save lands, or on Cancel. */
  onClose: () => void
}) {
  const [opened] = useState(() => scheduleOf(r))
  const [s, setS] = useState(opened)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const first = useRef<HTMLElement>(null)
  useEffect(() => { first.current?.focus() }, [])
  const set = (patch: Partial<Schedule>) => setS((x) => ({ ...x, ...patch }))

  const save = (e: React.FormEvent) => {
    e.preventDefault()
    // Unchanged: saving would move the reminder off its own next fire, a skipped one included.
    if ((Object.keys(s) as (keyof Schedule)[]).every((k) => s[k] === opened[k])) return onClose()
    setBusy(true)
    const fireAt = nextFireAt(s, new Date(), new Date(Date.parse(r.fireAt)))
    onReschedule(r.id, fireAt, REPEAT_MINUTES[s.repeat]).then(onClose, (err: unknown) => {
      setError(i18nT('apps.crewCompanion.reminders.couldnt_reschedule', { error: errorText(err) }))
      setBusy(false)
    })
  }

  return (
    // Escape cancels, as in the text editor; an open dropdown claims (preventDefault) its own Escape first.
    <form className="cc-rem-edit cc-rem-schedule" onSubmit={save}
      onKeyDown={(e) => { if (e.key === 'Escape' && !e.defaultPrevented) onClose() }}>
      <SimpleSelect ref={first} aria-label={i18nT('apps.crewCompanion.reminders.schedule_repeat_aria')}
        options={REPEATS} optionLabels={REPEATS.map((k) => REPEAT_LABEL[k]())}
        value={s.repeat} onChange={(v) => set({ repeat: v as Repeat })} />
      {s.repeat === 'weekly' ? (
        <SimpleSelect aria-label={i18nT('apps.crewCompanion.reminders.schedule_weekday_aria')}
          options={WEEKDAYS} optionLabels={WEEKDAYS.map((d) => fmtWeekday(Number(d), 'long'))}
          value={String(s.weekday)} onChange={(v) => set({ weekday: Number(v) })} />
      ) : null}
      {s.repeat === 'hourly' ? (
        <input type="number" className="cc-add-input" min={0} max={59} value={s.minute}
          aria-label={i18nT('apps.crewCompanion.reminders.schedule_minute_aria')}
          onChange={(e) => set({ minute: Math.min(59, Math.max(0, Math.trunc(Number(e.target.value)))) })} />
      ) : (
        <input type="time" className="cc-add-input" value={`${pad(s.hour)}:${pad(s.minute)}`}
          aria-label={i18nT('apps.crewCompanion.reminders.schedule_time_aria')}
          onChange={(e) => {
            // A cleared field keeps the last time rather than saving a guessed one.
            const [hour, minute] = e.target.value.split(':').map(Number)
            if (e.target.value) set({ hour, minute })
          }} />
      )}
      <button type="submit" className="cc-btn" disabled={busy}>{i18nT('apps.crewCompanion.editor.save')}</button>
      <button type="button" className="cc-btn" onClick={onClose}>{i18nT('apps.crewCompanion.editor.cancel')}</button>
      {/* No hand-off: the unsaved schedule is still in the fields above. */}
      <ErrorNotice message={error} variant="inline" />
    </form>
  )
}
