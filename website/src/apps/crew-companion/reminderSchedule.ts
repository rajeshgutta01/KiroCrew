/**
 * The hand-set schedule behind the reminder row's Change schedule editor: what the
 * editor opens with for an existing reminder, and the `{fireAt, everyMinutes}` it
 * saves. Local time throughout, the same clock the text parser reads.
 */
import type { Reminder } from './types'

/** Each Repeat choice and the interval it stores; `null` is one-time. */
export const REPEAT_MINUTES = { once: null, hourly: 60, daily: 1440, weekly: 10080 } as const
export type Repeat = keyof typeof REPEAT_MINUTES
export const REPEATS = Object.keys(REPEAT_MINUTES) as Repeat[]

export interface Schedule {
  repeat: Repeat
  /** Local clock time. Hourly reads only `minute`. */
  hour: number
  minute: number
  /** ISO weekday, 1 is Monday and 7 is Sunday. Weekly only. */
  weekday: number
}

const isoWeekday = (d: Date) => d.getDay() || 7

/** The editor's starting values: the reminder's next fire, and its repeat when the editor has one. */
export function scheduleOf(r: Reminder): Schedule {
  const at = new Date(Date.parse(r.fireAt))
  const every = r.recurrence?.everyMinutes ?? null
  return {
    repeat: REPEATS.find((k) => REPEAT_MINUTES[k] === every) ?? 'once',
    hour: at.getHours(),
    minute: at.getMinutes(),
    weekday: isoWeekday(at),
  }
}

/**
 * The schedule's first fire strictly after `now`, as the ISO instant the backend
 * stores. A one-time reminder keeps `day`, its own date, unless that has passed.
 */
export function nextFireAt(s: Schedule, now: Date, day: Date = now): string {
  if (s.repeat === 'hourly') {
    const at = new Date(now)
    at.setMinutes(s.minute, 0, 0)
    // Elapsed hours, not setHours, and a loop: inside the repeated hour of a fall-back
    // change, setMinutes lands on the first pass of that hour, two hours back.
    while (at <= now) at.setTime(at.getTime() + 3_600_000)
    return at.toISOString()
  }
  const at = new Date(s.repeat === 'once' ? day : now)
  at.setHours(s.hour, s.minute, 0, 0)
  // setDate, not +24h, so the first fire keeps the clock time across a daylight-saving change.
  while (at <= now || (s.repeat === 'weekly' && isoWeekday(at) !== s.weekday)) at.setDate(at.getDate() + 1)
  return at.toISOString()
}
