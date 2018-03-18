#!/bin/bash


NAME=$1
FPATH=$2
SER_IP=$3
TEST=$4



echo "<html>"
echo "Hi All"
echo "<br>"
echo "HTML Evasion Result"

echo "<br>"
echo "<br>"
echo "<table border=\"1\">"
echo "<tr>"
echo "<td>NAME :</td>"
echo "<td>$NAME</td>"
echo "</tr>"
echo "<tr>"
echo "<td>REPORT :</td>"
echo "<td><a href='http://$SER_IP/report/$FPATH/html_$TEST' target='_blank'> Report </td>"
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
	echo "<td> Testcase Name</td>"
	echo "<td> Evasion Name</td>"
	echo "<td> Payload Name </td>"
	echo "<td> Compress </td>"
	echo "<td> Chunked </td>"
	echo "<td> CharacterSet </td>"
	echo "<td> Result </td>"
    echo "</tr>"

sed 's/;wget.*$//' report/$FPATH/html_$TEST > /tmp/$FPATH_html_$TEST

for l in `cat /tmp/$FPATH_html_$TEST`
do

	testcase_name=`echo $l | cut -d ';' -f 1`
	html_evasion_name=`echo $l | cut -d ';' -f 2`
	file_name=`echo $l | cut -d ';' -f 3`
	compress=`echo $l | cut -d ';' -f 4`
	chunked=`echo $l | cut -d ';' -f 5`
	characterset=`echo $l | cut -d ';' -f 6`
        result=`echo $l | cut -d ';' -f 7`

	echo "<tr>"
	echo "<td>"
        echo $testcase_name
	echo "</td>"
	echo "<td>"
        echo $html_evasion_name
	echo "</td>"
	echo "<td>"
        echo $file_name
	echo "</td>"
	echo "<td>"
        echo $compress
	echo "</td>"
	echo "<td>"
        echo $chunked
	echo "</td>"
	echo "<td>"
        echo $characterset
	echo "</td>"
	if [ $result == "EvasionError" ]; then
		echo "<td>"
	fi
	if [ $result == "PASS" ]; then
		echo "<td>"
	fi
	if [ $result == "FAILED" ]; then
		echo '<td bgcolor="#FF0000">'
	fi
        echo $result
	echo "</td>"
	echo "</tr>"
	

done 
echo "</table>"
echo "<html>"
