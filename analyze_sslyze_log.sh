#!/bin/bash

timeouts=`cat sslyze_log | grep "WARNING: Could not connect (timeout); discarding corresponding tasks." | wc -l`
ehlo=`cat sslyze_log | grep "WARNING: SMTP EHLO was rejected; discarding corresponding tasks." | wc -l`
starttls=`cat sslyze_log | grep "WARNING: SMTP STARTTLS not supported; discarding corresponding tasks." | wc -l`
rejected=`cat sslyze_log | grep "WARNING: Connection rejected; discarding corresponding tasks." | wc -l`
finished=`cat sslyze_log | grep "Finished target " | wc -l`
total=`expr $timeouts + $ehlo + $starttls + $rejected + $finished`

one_p=`expr $total / 100`
timeouts_p=`expr $timeouts / $one_p`
ehlo_p=`expr $ehlo / $one_p`
starttls_p=`expr $starttls / $one_p`
rejected_p=`expr $rejected / $one_p`
finished_p=`expr $finished / $one_p`
total_p=`expr $timeouts_p + $ehlo_p + $starttls_p + $rejected_p + $finished_p`

echo
echo "SSLYZE LOG EVALUATION"
echo "====================="
echo
echo -e " Timeouts:\t\t\t$timeouts_p%\t$timeouts"
echo -e " EHLO command rejected:\t\t$ehlo_p%\t$ehlo"
echo -e " STARTTLS not supported:\t$starttls_p%\t$starttls"
echo -e " Connection rejected:\t\t$rejected_p%\t$rejected"
echo -e " Finished targets:\t\t$finished_p%\t$finished"
echo "==============================================="
echo -e " TOTAL:\t\t\t\t$total_p%\t$total"
echo
echo "(Percentage calculation is probably incorrect because of floating point errors!)"
echo

