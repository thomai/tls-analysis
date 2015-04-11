#!/bin/bash

timeouts=`cat sslyze_log | grep "WARNING: Could not connect (timeout); discarding corresponding tasks." | wc -l`
ehlo=`cat sslyze_log | grep "WARNING: SMTP EHLO was rejected; discarding corresponding tasks." | wc -l`
starttls=`cat sslyze_log | grep "WARNING: SMTP STARTTLS not supported; discarding corresponding tasks." | wc -l`
rejected=`cat sslyze_log | grep "WARNING: Connection rejected; discarding corresponding tasks." | wc -l`
finished=`cat sslyze_log | grep "Finished target " | wc -l`
total=`expr $timeouts + $ehlo + $starttls + $rejected + $finished`

scale="scale=2;"
one_p=`echo "$scale $total / 100" | bc`
timeouts_p=`echo "$scale $timeouts / $one_p" | bc`
ehlo_p=`echo "$scale $ehlo / $one_p" | bc`
starttls_p=`echo "$scale $starttls / $one_p" | bc`
rejected_p=`echo "$scale $rejected / $one_p" | bc`
finished_p=`echo "$scale $finished / $one_p" | bc`
total_p=`echo "$scale $timeouts_p + $ehlo_p + $starttls_p + $rejected_p + $finished_p" | bc`

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

