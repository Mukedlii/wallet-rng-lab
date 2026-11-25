import os,requests
def send(message):
 token=os.getenv("TELEGRAM_BOT_TOKEN"); chat=os.getenv("TELEGRAM_CHAT_ID")
 if not token or not chat: return False
 r=requests.post("https://api.telegram.org/bot"+token+"/sendMessage",json={"chat_id":chat,"text":message[:3900],"disable_web_page_preview":True},timeout=15); r.raise_for_status()
 return bool(r.json().get("ok"))
