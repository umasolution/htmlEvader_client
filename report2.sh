#!/bin/bash


NAME=$1
FPATH=$2
SRVIP=$3



echo "<html>"
echo "Hi All"
echo "<br>"
echo "HTML Evasion Result"

echo "<br>"
echo "<br>"
echo "<table border=\"1\">"
echo "<tr>"
echo "<td>Name :</td>"
echo "<td>$NAME</td>"
echo "</tr>"
echo "</table>"

echo "<br>"
    echo "<table>"
    echo "<tr>"
    echo "<td> Priority </td>"
    echo "<td bgcolor="#FF0000"> Failed </td>"
    echo "<td bgcolor="#008000"> Passed </td>"
    echo "</tr>"
    echo "</table>"
    echo "<br>"


	echo "<table border=\"1\">"
	echo "<tr>"
	echo "<td> File Name</td>"
	echo "<td> PASS </td>"
    echo "<td> FAIL </td>"
    echo "<td> Evasion Error </td>"
    echo "</tr>"

for l in `ls report/$FPATH/html_*`
do
        filename=`echo $l | tr '/' ' ' | awk '{print $3}'`

        failed=`grep 'FAILED' $l | wc -l`

        pass=`grep 'PASS' $l | wc -l`

        EvasionError=`grep 'EvasionError' $l | wc -l`

        count1=`cat report/$FPATH/$filename | wc -l`

        if [ "$count1" -eq 1 ]; then
                EvasionError="Signature Not Found"
        fi
	echo "<tr>"
	echo "<td>"
	echo "<a href=\"http://$SRVIP/report/$FPATH/$filename\"> $filename </a>"
	echo "</td>"
	echo "<td>"
	echo $pass
	echo "</td>"
	echo "<td>"
	echo $failed
	echo "</td>"
	echo "<td>"
	echo $EvasionError
	echo "</td>"
	echo "</tr>"
	

done

echo "</table>"
echo "<html>"
