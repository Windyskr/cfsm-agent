package cfprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func interfaceTrafficFile(basePath, name string) string {
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, name)
	return filepath.Join(filepath.Dir(basePath), "traffic-interface-"+clean+".dat")
}

// resetSchedule is when the traffic period restarts: on Day (1-31, 0 = never)
// at Minute minutes past midnight in Location (nil = the agent's local zone).
type resetSchedule struct {
	Day      int
	Minute   int
	Location *time.Location
}

func (cfg Config) trafficResetSchedule() resetSchedule {
	schedule := resetSchedule{Day: cfg.ResetDay}
	if minute, ok := parseResetTime(cfg.ResetTime); ok {
		schedule.Minute = minute
	}
	if offset, ok := parseResetUTCOffset(cfg.ResetUTCOffset); ok {
		sign, abs := '+', offset
		if offset < 0 {
			sign, abs = '-', -offset
		}
		schedule.Location = time.FixedZone(fmt.Sprintf("UTC%c%02d:%02d", sign, abs/60, abs%60), offset*60)
	}
	return schedule
}

func (s resetSchedule) zoneName() string {
	if s.Location == nil {
		return "本机时区"
	}
	return s.Location.String()
}

func calcMonthlyTrafficByInterface(basePath string, current map[string]NetBytes, schedule resetSchedule) map[string]NetBytes {
	if len(current) == 0 {
		return nil
	}
	result := make(map[string]NetBytes, len(current))
	for name, counters := range current {
		rx, tx := calcMonthlyTraffic(interfaceTrafficFile(basePath, name), counters, schedule, name)
		result[name] = NetBytes{RX: rx, TX: tx}
	}
	return result
}

type trafficState struct {
	RXPrev      uint64
	TXPrev      uint64
	RXPeriod    uint64
	TXPeriod    uint64
	LastCheck   int64
	PeriodStart int64
	Interface   string
}

func readTrafficState(path string) trafficState {
	values, err := parseKVFile(path)
	if err != nil {
		return trafficState{}
	}
	return trafficState{
		RXPrev:      parseUintDefault(values["RX_PREV"], 0),
		TXPrev:      parseUintDefault(values["TX_PREV"], 0),
		RXPeriod:    parseUintDefault(values["RX_PERIOD"], 0),
		TXPeriod:    parseUintDefault(values["TX_PERIOD"], 0),
		LastCheck:   atoi64Default(values["LAST_CHECK"], 0),
		PeriodStart: atoi64Default(values["PERIOD_START"], 0),
		Interface:   values["INTERFACE"],
	}
}

func writeTrafficState(path string, st trafficState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data := fmt.Sprintf("RX_PREV=%d\nTX_PREV=%d\nRX_PERIOD=%d\nTX_PERIOD=%d\nLAST_CHECK=%d\nPERIOD_START=%d\nINTERFACE=%s\n",
		st.RXPrev, st.TXPrev, st.RXPeriod, st.TXPeriod, st.LastCheck, st.PeriodStart, st.Interface)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func calcMonthlyTraffic(path string, current NetBytes, schedule resetSchedule, iface string) (uint64, uint64) {
	nowTime := time.Now()
	now := nowTime.Unix()
	st := readTrafficState(path)
	if st.Interface != iface {
		st = trafficState{}
	}
	periodStart := periodStartTS(nowTime, schedule)
	if st.LastCheck == 0 {
		st.RXPrev = current.RX
		st.TXPrev = current.TX
		st.LastCheck = now
		st.PeriodStart = periodStart
		st.Interface = iface
		_ = writeTrafficState(path, st)
		return st.RXPeriod, st.TXPeriod
	}

	var rxDelta, txDelta uint64
	if current.RX >= st.RXPrev {
		rxDelta = current.RX - st.RXPrev
	}
	if current.TX >= st.TXPrev {
		txDelta = current.TX - st.TXPrev
	}
	// Start a new period only when a reset moment passed since the last
	// sample. If just the schedule changed (reset day or time edited mid-period),
	// the stored start moves and the traffic counted so far is kept.
	if periodStart != 0 && st.PeriodStart != 0 && periodStart != st.PeriodStart &&
		periodStartTS(time.Unix(st.LastCheck, 0), schedule) != periodStart {
		st.RXPeriod = rxDelta
		st.TXPeriod = txDelta
	} else {
		st.RXPeriod += rxDelta
		st.TXPeriod += txDelta
	}
	st.RXPrev = current.RX
	st.TXPrev = current.TX
	st.LastCheck = now
	st.PeriodStart = periodStart
	st.Interface = iface
	_ = writeTrafficState(path, st)
	return st.RXPeriod, st.TXPeriod
}

func applyTrafficCorrection(path string, current NetBytes, iface string, rxGB, txGB string) error {
	rx, err := parseTrafficCorrectionGB(rxGB)
	if err != nil {
		return err
	}
	tx, err := parseTrafficCorrectionGB(txGB)
	if err != nil {
		return err
	}
	st := readTrafficState(path)
	st.RXPrev = current.RX
	st.TXPrev = current.TX
	st.RXPeriod = rx
	st.TXPeriod = tx
	st.LastCheck = time.Now().Unix()
	st.Interface = iface
	return writeTrafficState(path, st)
}

func periodStartTS(now time.Time, schedule resetSchedule) int64 {
	if schedule.Day == 0 {
		return 0
	}
	if schedule.Day < 1 || schedule.Day > 31 {
		return now.Unix()
	}
	if schedule.Location != nil {
		now = now.In(schedule.Location)
	}
	return lastResetDate(now, schedule.Day, schedule.Minute).Unix()
}

func lastResetDate(now time.Time, resetDay, resetMinute int) time.Time {
	year, month, _ := now.Date()
	loc := now.Location()
	thisMonth := actualResetDate(year, month, resetDay, resetMinute, loc)
	if !now.Before(thisMonth) {
		return thisMonth
	}
	prevMonth := month - 1
	prevYear := year
	if prevMonth < time.January {
		prevMonth = time.December
		prevYear--
	}
	return actualResetDate(prevYear, prevMonth, resetDay, resetMinute, loc)
}

func actualResetDate(year int, month time.Month, resetDay, resetMinute int, loc *time.Location) time.Time {
	firstDayOfNextMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, loc)
	lastDayOfMonth := firstDayOfNextMonth.AddDate(0, 0, -1).Day()
	if resetDay <= lastDayOfMonth {
		return time.Date(year, month, resetDay, 0, resetMinute, 0, 0, loc)
	}
	nextMonth := month + 1
	nextYear := year
	if nextMonth > time.December {
		nextMonth = time.January
		nextYear++
	}
	return time.Date(nextYear, nextMonth, 1, 0, resetMinute, 0, 0, loc)
}

func parseUintDefault(raw string, def uint64) uint64 {
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return def
	}
	return n
}
