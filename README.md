# ai-powered auto pentest & code security

hey, this is an automated pentest and code security tool i built by fine-tuning a llama-3.2 3b model. it finds vulnerabilities in code and runs nmap/nikto scans in the background.

## features
* **ai code audit:** fine-tuned llama model scans your code and finds security flaws instantly.
* **auto scanning:** integrated with nmap and nikto for network-level reconnaissance.
* **live monitoring:** a client agent watches your folders and uploads new files for evaluation automatically.
* **secure:** includes csrf protection, rate limiting, and token-based auth.

## tech stack
* **backend:** flask (python 3.12)
* **ai:** llama-3.2-3b (fine-tuned using unsloth)
* **frontend:** simple html/js, css is ai-generated (styles.css ai written).

## project structure
* `app.py`: core server handling ai inference and scan orchestration.
* `client.py`: monitor agent for local file tracking and remote upload.
* `fine-tune.py`: script used to train the model on security datasets.

## license
**agplv3** - if you use or modify this code, you must share your source too. no stealing!
