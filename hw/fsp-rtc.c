/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <lock.h>
#include <time.h>

//#define DBG(fmt...)	printf("RTC: " fmt)
#define DBG(fmt...)	do { } while(0)

/*
 * Note on how those operate:
 *
 * Because the RTC calls can be pretty slow, these functions will shoot
 * an asynchronous request to the FSP (if none is already pending)
 *
 * The requests will return OPAL_BUSY_EVENT as long as the event has
 * not been completed.
 *
 * WARNING: An attempt at doing an RTC write while one is already pending
 * will simply ignore the new arguments and continue returning
 * OPAL_BUSY_EVENT. This is to be compatible with existing Linux code.
 *
 * Completion of the request will result in an event OPAL_EVENT_RTC
 * being signaled, which will remain raised until a corresponding call
 * to opal_rtc_read() or opal_rtc_write() finally returns OPAL_SUCCESS,
 * at which point the operation is complete and the event cleared.
 *
 * There is two separate set of state for reads and writes. If both are
 * attempted at the same time, the event bit will remain set as long as
 * either of the two has a pending event to signal.
 */

static struct lock rtc_lock;
static struct fsp_msg *rtc_read_msg;
static struct fsp_msg *rtc_write_msg;

static int days_in_month(int month, int year)
{
	static int month_days[] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	};

	assert(1 <= month && month <= 12);

	/* we may need to update this in the year 4000, pending a
	 * decision on whether or not it's a leap year */
	if (month == 2) {
		bool is_leap = !(year % 400) || ((year % 100) && !(year % 4));
		return is_leap ? 29 : 28;
	}

	return month_days[month - 1];
}

static void tm_add(struct tm *in, struct tm *out, unsigned long secs)
{
	unsigned long year, month, mday, hour, minute, second, d;
	static const unsigned long sec_in_400_years =
		((3903ul * 365) + (97 * 366)) * 24 * 60 * 60;

	assert(in);
	assert(out);

	second = in->tm_sec;
	minute = in->tm_min;
	hour = in->tm_hour;
	mday = in->tm_mday;
	month = in->tm_mon;
	year = in->tm_year;

	second += secs;

	/* There are the same number of seconds in any 400-year block; this
	 * limits the iterations in the loop below */
	year += 400 * (second / sec_in_400_years);
	second = second % sec_in_400_years;

	if (second >= 60) {
		minute += second / 60;
		second = second % 60;
	}

	if (minute >= 60) {
		hour += minute / 60;
		minute = minute % 60;
	}

	if (hour >= 24) {
		mday += hour / 24;
		hour = hour % 24;
	}

	for (d = days_in_month(month, year); mday >= d;
			d = days_in_month(month, year)) {
		month++;
		if (month > 12) {
			month = 1;
			year++;
		}
		mday -= d;
	}

	out->tm_year = year;
	out->tm_mon = month;
	out->tm_mday = mday;
	out->tm_hour = hour;
	out->tm_min = minute;
	out->tm_sec = second;
}

static void opal_rtc_eval_events(void)
{
	bool pending = false;

	if (rtc_read_msg && !fsp_msg_busy(rtc_read_msg))
		pending = true;
	if (rtc_write_msg && !fsp_msg_busy(rtc_write_msg))
		pending = true;
	opal_update_pending_evt(OPAL_EVENT_RTC, pending ? OPAL_EVENT_RTC : 0);
}

static void opal_rtc_req_complete(struct fsp_msg *msg __unused)
{
	lock(&rtc_lock);
	DBG("Req completion %p\n", msg);
	opal_rtc_eval_events();
	unlock(&rtc_lock);
}

static int64_t opal_rtc_decode_msg(struct fsp_msg *msg, uint32_t *y_m_d,
				   uint64_t *h_m_s_m)
{
	uint8_t rc;

	if (!msg || msg->state != fsp_msg_response)
		return OPAL_INTERNAL_ERROR;

	/* The OPAL wiki mention a special result code of
	 * OPAL_HARDWARE_UNINITIALIZED in the event where
	 * the TOD needs an initial write before containing
	 * any useful value. However the actual result code
	 * value isn't defined... and Linux doesn't deal with
	 * it, so just return OPAL_HARDWARE
	 */
	rc = (msg->word1 >> 8) & 0xff;
	if (rc != 0)
		return OPAL_HARDWARE;

	*y_m_d = msg->data.words[0];

	/* The FSP returns in BCD
	 *
	 *  |  hour  | minutes | secs  | reserved |
	 *  | -------------------------------------
	 *  |              microseconds           |
	 *
	 * The OPAL API is defined as returned a u64 of a
	 * similar format except that microseconds is milliseconds
	 * in OPAL and is flush with seconds (the reserved bits are
	 * at the bottom):
	 *
	 *  |  hour  | minutes | secs  | millisec |
	 *  | -------------------------------------
	 *  |        millisec          | reserved |
	 *
	 * We simply ignore the microseconds/milliseconds for now
	 * as I don't quite understand why the OPAL API defines that
	 * it needs 6 digits for the milliseconds :-) I suspect the
	 * doc got that wrong and it's supposed to be micro but
	 * let's ignore it.
	 *
	 * Note that Linux doesn't use nor set the ms field anyway.
	 */
	*h_m_s_m = (((uint64_t)msg->data.words[1]) & 0xffffff00) << 32;

	return OPAL_SUCCESS;
}

static int64_t opal_rtc_read(uint32_t *year_month_day,
			     uint64_t *hour_minute_second_millisecond)
{
	struct fsp_msg *msg;
	int64_t rc;

	if (!year_month_day || !hour_minute_second_millisecond)
		return OPAL_PARAMETER;

	lock(&rtc_lock);

	DBG("Got opal_rtc_read() call...\n");

	/* Do we have a request already ? */
	msg = rtc_read_msg;
	if (msg) {
		DBG("Pending request @%p, state=%d\n", msg, msg->state);

		/* If it's still in progress, return */
		if (fsp_msg_busy(msg)) {
			DBG(" -> busy\n");
			/* Don't free the message */
			msg = NULL;
			rc = OPAL_BUSY_EVENT;
			goto bail;
		}

		/* It's complete, clear events */
		rtc_read_msg = NULL;
		opal_rtc_eval_events();


		/* Check error state */
		if (msg->state != fsp_msg_done) {
			DBG(" -> request not in done state -> error !\n");
			rc = OPAL_INTERNAL_ERROR;
			goto bail;
		}
		/* Check response */
		rc = opal_rtc_decode_msg(msg->resp, year_month_day,
					 hour_minute_second_millisecond);
		DBG(" -> decode result: %lld\n", rc);
		goto bail;
	}

	DBG("Sending new read request...\n");

	/* Create a request and send it */
	rtc_read_msg = fsp_mkmsg(FSP_CMD_READ_TOD, 0);
	if (!rtc_read_msg) {
		DBG(" -> allocation failed !\n");
		rc = OPAL_INTERNAL_ERROR;
		goto bail;
	}
	DBG(" -> req at %p\n", rtc_read_msg);
	if (fsp_queue_msg(rtc_read_msg, opal_rtc_req_complete)) {
		DBG(" -> queueing failed !\n");
		rc = OPAL_INTERNAL_ERROR;
		fsp_freemsg(rtc_read_msg);
		rtc_read_msg = NULL;
		goto bail;
	}
	rc = OPAL_BUSY_EVENT;
 bail:
	unlock(&rtc_lock);
	if (msg)
		fsp_freemsg(msg);
	DBG(" -> opal ret=%lld\n", rc);
	return rc;
}
opal_call(OPAL_RTC_READ, opal_rtc_read);

static int64_t opal_rtc_write(uint32_t year_month_day __unused,
			      uint64_t hour_minute_second_millisecond __unused)
{
	struct fsp_msg *msg;
	uint32_t w0, w1, w2;
	int64_t rc;

	lock(&rtc_lock);

	DBG("Got opal_rtc_write() call...\n");

	/* Do we have a request already ? */
	msg = rtc_write_msg;
	if (msg) {
		DBG("Pending request @%p, state=%d\n", msg, msg->state);

		/* If it's still in progress, return */
		if (fsp_msg_busy(msg)) {
			DBG(" -> busy\n");
			/* Don't free the message */
			msg = NULL;
			rc = OPAL_BUSY_EVENT;
			goto bail;
		}

		/* It's complete, clear events */
		rtc_write_msg = NULL;
		opal_rtc_eval_events();

		/* Check error state */
		if (msg->state != fsp_msg_done) {
			DBG(" -> request not in done state -> error !\n");
			rc = OPAL_INTERNAL_ERROR;
			goto bail;
		}
		rc = OPAL_SUCCESS;
		goto bail;
	}

	DBG("Sending new write request...\n");

	/* Create a request and send it. Just like for read, we ignore
	 * the "millisecond" field which is probably supposed to be
	 * microseconds and which Linux ignores as well anyway
	 */
	w0 = year_month_day;
	w1 = (hour_minute_second_millisecond >> 32) & 0xffffff00;
	w2 = 0;
	
	rtc_write_msg = fsp_mkmsg(FSP_CMD_WRITE_TOD, 3, w0, w1, w2);
	if (!rtc_write_msg) {
		DBG(" -> allocation failed !\n");
		rc = OPAL_INTERNAL_ERROR;
		goto bail;
	}
	DBG(" -> req at %p\n", rtc_read_msg);
	if (fsp_queue_msg(rtc_write_msg, opal_rtc_req_complete)) {
		DBG(" -> queueing failed !\n");
		rc = OPAL_INTERNAL_ERROR;
		fsp_freemsg(rtc_write_msg);
		rtc_write_msg = NULL;
		goto bail;
	}
	rc = OPAL_BUSY_EVENT;
 bail:
	unlock(&rtc_lock);
	if (msg)
		fsp_freemsg(msg);
	DBG(" -> opal ret=%lld\n", rc);

	return rc;
}
opal_call(OPAL_RTC_WRITE, opal_rtc_write);
