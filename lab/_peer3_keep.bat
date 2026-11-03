@echo off
REM 启动 M3 客户端并保持窗口常驻
cd /d c:\Users\30952\Desktop\AuditForwarder_ovo1102
echo === M3 client starting ===
echo proxy: 127.0.0.1:8888
echo target host: 26.17.173.34
echo host_id: lab-pc3
echo operator: admin3
echo Press Ctrl+C to stop.
echo ==========================
build\auditforwarder-client.exe -c config\client_lab_peer3.yaml -d data\client3
pause
