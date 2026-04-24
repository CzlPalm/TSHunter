(fritap-env) palm@palm-Dell-Pro-Tower-QCT1250:~/桌面/tls_capture_t5.1/tls_captur
e$ python3 tools/chrome_downloader.py --list
113	113.0.5672.63	https://storage.googleapis.com/chrome-for-testing-public/113.0.5672.63/linux64/chrome-linux64.zip
114	114.0.5735.133	https://storage.googleapis.com/chrome-for-testing-public/114.0.5735.133/linux64/chrome-linux64.zip
115	115.0.5790.170	https://storage.googleapis.com/chrome-for-testing-public/115.0.5790.170/linux64/chrome-linux64.zip
116	116.0.5845.96	https://storage.googleapis.com/chrome-for-testing-public/116.0.5845.96/linux64/chrome-linux64.zip
117	117.0.5938.149	https://storage.googleapis.com/chrome-for-testing-public/117.0.5938.149/linux64/chrome-linux64.zip
118	118.0.5993.70	https://storage.googleapis.com/chrome-for-testing-public/118.0.5993.70/linux64/chrome-linux64.zip
119	119.0.6045.105	https://storage.googleapis.com/chrome-for-testing-public/119.0.6045.105/linux64/chrome-linux64.zip
120	120.0.6099.109	https://storage.googleapis.com/chrome-for-testing-public/120.0.6099.109/linux64/chrome-linux64.zip
121	121.0.6167.184	https://storage.googleapis.com/chrome-for-testing-public/121.0.6167.184/linux64/chrome-linux64.zip
122	122.0.6261.128	https://storage.googleapis.com/chrome-for-testing-public/122.0.6261.128/linux64/chrome-linux64.zip
123	123.0.6312.122	https://storage.googleapis.com/chrome-for-testing-public/123.0.6312.122/linux64/chrome-linux64.zip
124	124.0.6367.207	https://storage.googleapis.com/chrome-for-testing-public/124.0.6367.207/linux64/chrome-linux64.zip
125	125.0.6422.141	https://storage.googleapis.com/chrome-for-testing-public/125.0.6422.141/linux64/chrome-linux64.zip
126	126.0.6478.182	https://storage.googleapis.com/chrome-for-testing-public/126.0.6478.182/linux64/chrome-linux64.zip
127	127.0.6533.119	https://storage.googleapis.com/chrome-for-testing-public/127.0.6533.119/linux64/chrome-linux64.zip
128	128.0.6613.137	https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.137/linux64/chrome-linux64.zip
129	129.0.6668.100	https://storage.googleapis.com/chrome-for-testing-public/129.0.6668.100/linux64/chrome-linux64.zip
130	130.0.6723.116	https://storage.googleapis.com/chrome-for-testing-public/130.0.6723.116/linux64/chrome-linux64.zip
131	131.0.6778.264	https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.264/linux64/chrome-linux64.zip
132	132.0.6834.159	https://storage.googleapis.com/chrome-for-testing-public/132.0.6834.159/linux64/chrome-linux64.zip
133	133.0.6943.141	https://storage.googleapis.com/chrome-for-testing-public/133.0.6943.141/linux64/chrome-linux64.zip
134	134.0.6998.165	https://storage.googleapis.com/chrome-for-testing-public/134.0.6998.165/linux64/chrome-linux64.zip
135	135.0.7049.114	https://storage.googleapis.com/chrome-for-testing-public/135.0.7049.114/linux64/chrome-linux64.zip
136	136.0.7103.113	https://storage.googleapis.com/chrome-for-testing-public/136.0.7103.113/linux64/chrome-linux64.zip
137	137.0.7151.119	https://storage.googleapis.com/chrome-for-testing-public/137.0.7151.119/linux64/chrome-linux64.zip
138	138.0.7204.183	https://storage.googleapis.com/chrome-for-testing-public/138.0.7204.183/linux64/chrome-linux64.zip
139	139.0.7258.154	https://storage.googleapis.com/chrome-for-testing-public/139.0.7258.154/linux64/chrome-linux64.zip
140	140.0.7339.207	https://storage.googleapis.com/chrome-for-testing-public/140.0.7339.207/linux64/chrome-linux64.zip
141	141.0.7390.122	https://storage.googleapis.com/chrome-for-testing-public/141.0.7390.122/linux64/chrome-linux64.zip
142	142.0.7444.175	https://storage.googleapis.com/chrome-for-testing-public/142.0.7444.175/linux64/chrome-linux64.zip
143	143.0.7499.192	https://storage.googleapis.com/chrome-for-testing-public/143.0.7499.192/linux64/chrome-linux64.zip
144	144.0.7559.133	https://storage.googleapis.com/chrome-for-testing-public/144.0.7559.133/linux64/chrome-linux64.zip
145	145.0.7632.117	https://storage.googleapis.com/chrome-for-testing-public/145.0.7632.117/linux64/chrome-linux64.zip
146	146.0.7680.165	https://storage.googleapis.com/chrome-for-testing-public/146.0.7680.165/linux64/chrome-linux64.zip
147	147.0.7727.56	https://storage.googleapis.com/chrome-for-testing-public/147.0.7727.56/linux64/chrome-linux64.zip
148	148.0.7778.6	https://storage.googleapis.com/chrome-for-testing-public/148.0.7778.6/linux64/chrome-linux64.zip
149	149.0.7790.0	https://storage.googleapis.com/chrome-for-testing-public/149.0.7790.0/linux64/chrome-linux64.zip
(fritap-env) palm@palm-Dell-Pro-Tower-QCT1250:~/桌面/tls_capture_t5.1/tls_captur
e$ python3 tools/chrome_downloader.py \
  --milestones 140,142,143 \
  --output-dir artifacts/chrome
[*] 输出目录: artifacts/chrome
[*] 目标 milestone: 140, 142, 143
[DOWN] milestone=140 version=140.0.7339.207
       url=https://storage.googleapis.com/chrome-for-testing-public/140.0.7339.207/linux64/chrome-linux64.zip
/home/palm/桌面/tls_capture_t5.1/tls_capture/tools/chrome_downloader.py:160: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  'downloaded_at_utc': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
[OK] 140.0.7339.207 -> artifacts/chrome/140.0.7339.207/chrome
[DOWN] milestone=142 version=142.0.7444.175
       url=https://storage.googleapis.com/chrome-for-testing-public/142.0.7444.175/linux64/chrome-linux64.zip
/home/palm/桌面/tls_capture_t5.1/tls_capture/tools/chrome_downloader.py:160: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  'downloaded_at_utc': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
[OK] 142.0.7444.175 -> artifacts/chrome/142.0.7444.175/chrome
[DOWN] milestone=143 version=143.0.7499.192
       url=https://storage.googleapis.com/chrome-for-testing-public/143.0.7499.192/linux64/chrome-linux64.zip
/home/palm/桌面/tls_capture_t5.1/tls_capture/tools/chrome_downloader.py:160: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  'downloaded_at_utc': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
[OK] 143.0.7499.192 -> artifacts/chrome/143.0.7499.192/chrome

