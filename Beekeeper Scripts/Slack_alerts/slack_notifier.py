import os
import pika
import json
import requests
import time
from collections import defaultdict

#webhook now comes from the environment (.env next to docker-compose.yml) so it is not
#hardcoded in this file or baked into the image layer
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "").strip()
if not WEBHOOK_URL:
    raise SystemExit("WEBHOOK_URL is not set - add it to .env next to docker-compose.yml")

#platform settings - set PLATFORM to "discord" or "slack", everything below follows from it
PLATFORM = os.environ.get("PLATFORM", "discord").strip().lower()
PAYLOAD_KEY = "content" if PLATFORM == "discord" else "text"  #discord wants content, slack wants text
BOLD = "**" if PLATFORM == "discord" else "*"                 #discord needs ** for bold, slack uses a single *

#connection settings
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RECONNECT_SECONDS = 5                   #wait this long before retrying a dropped/refused connection
WEBHOOK_TIMEOUT_SECONDS = 10            #never block the consumer on a hung webhook

#filter settings
#statuses that carry no attacker action: the SSH session open/close bookkeeping.
#an SSH session emits four events - Stateless (login), Start, one Interaction per
#command, then End - and only the first and third are worth alerting on.
SKIP_STATUSES = {"Start", "End"}
IGNORE_PATHS = {"/examplepath.ico"}     #ignored path
PROBE_THRESHOLD = 1                     #need this many requests from an IP before it counts as "active probing",   [IMPORTANT]!!!!!!!!put at 1 for testing!!!!!!!![IMPORTANT]
PROBE_WINDOW_SECONDS = 60               #within this time window
COOLDOWN_SECONDS = 300                  #once alerted, don't alert on that IP again for 5 min

#in-memory state (resets if the script restarts)
last_alerted = {}                      #ip -> timestamp of last alert sent
request_times = defaultdict(list)      #ip -> list of recent request timestamps


#alert filter
def should_alert(ip, path, action):
    now = time.time()

    if path in IGNORE_PATHS:
        return False

    #record this request, then drop anything outside the window
    request_times[ip].append(now)
    request_times[ip] = [t for t in request_times[ip] if now - t <= PROBE_WINDOW_SECONDS]

    if len(request_times[ip]) < PROBE_THRESHOLD:
        return False  #too few requests yet to call this active probing

    #cooldown is keyed on the IP AND what it did, not the IP alone. keyed on the IP
    #alone, the SSH login attempt claimed the alert and every command typed in the
    #next 5 minutes was suppressed - i.e. the interesting half of the session was
    #the half you never heard about. this way a repeated identical action is still
    #throttled, but a new command or a new URL always gets through
    key = (ip, action)
    if key in last_alerted and now - last_alerted[key] < COOLDOWN_SECONDS:
        return False  #already alerted on this exact activity recently

    last_alerted[key] = now
    return True


#message details
def format_message(details):
    #http events fill RequestURI, ssh/tcp events fill Command instead. beelzebub always
    #sends both keys (empty string when unused), so test the value not the key
    request = details.get("RequestURI") or details.get("Command") or ""
    http_method = details.get("HTTPMethod") or ""
    request_line = f"{http_method} {request}".strip()

    msg = (
        f"Active probing detected\n"
        f"{BOLD}Time:{BOLD} {details.get('DateTime', '')}\n"
        f"{BOLD}Protocol:{BOLD} {details.get('Protocol', '')}\n"
        f"{BOLD}Source IP:{BOLD} {details.get('SourceIp', '')}\n"
        f"{BOLD}Service:{BOLD} {details.get('Description', '')}\n"
        f"{BOLD}Event:{BOLD} {details.get('Msg', '')}\n"
        f"{BOLD}Request:{BOLD} {request_line or '(none)'}"
    )

    #login attempts carry credentials; command events carry the honeypot's reply
    user = details.get("User") or ""
    password = details.get("Password") or ""
    if user or password:
        msg += f"\n{BOLD}Credentials:{BOLD} {user} / {password}"

    output = (details.get("CommandOutput") or "").strip()
    if output:
        #this is the LLM's answer - the actual research payload. keep it well under
        #Discord's 2000 char message cap
        if len(output) > 900:
            output = output[:900] + "\n... (truncated)"
        msg += f"\n{BOLD}Response given:{BOLD}\n```\n{output}\n```"

    return msg


#message alert
def on_message(ch, method, properties, body):
    #beelzebub marshals the event struct straight onto the queue, so the body is already
    #the flat event - there is no "event" wrapper to unpack (that nesting is only in its logs)
    try:
        details = json.loads(body)
    except json.JSONDecodeError as error:
        print(f"Skipping unparseable message: {error}")
        return

    #session open/close bookkeeping carries no attacker action - drop it before
    #it can consume an alert slot
    status = details.get("Status") or ""
    if status in SKIP_STATUSES:
        print(f"Skipping {status} event ({details.get('Msg', '')})")
        return

    #same trap as RequestURI: the key is always present, so a default never fires
    ip = details.get("SourceIp") or ""
    path = details.get("RequestURI") or ""
    #what the attacker actually did: a URL for HTTP, a typed command for SSH/TCP
    action = path or details.get("Command") or f"<{status} login>"
    if not ip:
        print(f"Skipping event with no source IP ({details.get('Msg', '')})")
        return

    if not should_alert(ip, path, action):
        print(f"Suppressed repeat from {ip} ({action})")
        return

    try:
        response = requests.post(
            WEBHOOK_URL,
            json={PAYLOAD_KEY: format_message(details)},
            timeout=WEBHOOK_TIMEOUT_SECONDS,
        )
    except requests.RequestException as error:
        #a webhook problem must not take the consumer down with it
        print(f"Webhook post failed for {ip}: {error}")
        return

    if response.ok:
        print(f"Alert sent for {ip}")
    else:
        #without this a rejected payload looks identical to a delivered one
        print(f"Webhook rejected alert for {ip}: {response.status_code} {response.text}")


#consume loop. rabbitmq takes 10-30s to accept connections on a cold boot and
#docker's depends_on only waits for the container to start, so the first few attempts
#are expected to fail. this also recovers if rabbitmq restarts later on
def consume_forever():
    print(f"slack-notifier starting, platform={PLATFORM}, broker={RABBITMQ_HOST}")

    while True:
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBITMQ_HOST, heartbeat=60)
            )
            channel = connection.channel()
            #must match the declaration in internal/builder/builder.go (non-durable)
            channel.queue_declare(queue="event")
            channel.basic_consume(queue="event", on_message_callback=on_message, auto_ack=True)
            print("Listening for events")
            channel.start_consuming()
        except pika.exceptions.AMQPError as error:
            print(f"RabbitMQ unavailable ({error}), retrying in {RECONNECT_SECONDS}s")
            time.sleep(RECONNECT_SECONDS)
        except KeyboardInterrupt:
            print("Shutting down")
            return


if __name__ == "__main__":
    consume_forever()