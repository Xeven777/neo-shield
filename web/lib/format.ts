export function formatDateTime(value: Date | string) {
  const date = typeof value === "string" ? new Date(value) : value
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date)
}

export function formatDate(value: Date | string) {
  const date = typeof value === "string" ? new Date(value) : value
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeZone: "UTC",
  }).format(date)
}

export function formatRelativeTime(value: Date | string | null | undefined) {
  if (!value) return "never"
  const date = typeof value === "string" ? new Date(value) : value
  const seconds = Math.round((date.getTime() - Date.now()) / 1000)
  const divisions: [number, Intl.RelativeTimeFormatUnit][] = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [7, "day"],
    [4.34524, "week"],
    [12, "month"],
    [Number.POSITIVE_INFINITY, "year"],
  ]

  let amount = seconds
  for (const [divisor, unit] of divisions) {
    if (Math.abs(amount) < divisor) {
      return new Intl.RelativeTimeFormat("en", { numeric: "auto" }).format(
        Math.round(amount),
        unit
      )
    }
    amount /= divisor
  }

  return formatDate(date)
}

export function titleCase(value: string) {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase())
}

export function pluralize(count: number, singular: string, plural?: string) {
  return `${count} ${count === 1 ? singular : (plural ?? `${singular}s`)}`
}
