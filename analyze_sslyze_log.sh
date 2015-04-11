#!/bin/bash

timeouts=`cat sslyze_log | grep "WARNING: Could not connect (timeout); discarding corresponding tasks." | wc -l`
echo -e "Timeouts:\t\t$timeouts"

ehlo=`cat sslyze_log | grep "WARNING: SMTP EHLO was rejected; discarding corresponding tasks." | wc -l`
echo -e "EHLO command rejected:\t$ehlo"

starttls=`cat sslyze_log | grep "WARNING: SMTP STARTTLS not supported; discarding corresponding tasks." | wc -l`
echo -e "STARTTLS not supported:\t$starttls"

rejected=`cat sslyze_log | grep "WARNING: Connection rejected; discarding corresponding tasks." | wc -l`
echo -e "Connection rejected:\t$rejected"

finished=`cat sslyze_log | grep "Finished target " | wc -l`
echo -e "Finished targets:\t$finished"

echo "============================="
total=`expr $timeouts + $ehlo + $starttls + $rejected + $finished`
echo -e "Total:\t\t\t$total"
echo

