import asyncio,subprocess,time,os,sys
from playwright.async_api import async_playwright
async def main():
 proc=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8777'],cwd=os.path.join(os.path.dirname(__file__),'..','backend'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);time.sleep(1)
 try:
  async with async_playwright() as pw:
   b=await pw.chromium.launch(headless=True, executable_path='/usr/bin/chromium', args=['--no-sandbox']);p=await b.new_page(viewport={'width':1440,'height':900});await p.goto('http://127.0.0.1:8777/');await p.fill('#email','admin@localhost');await p.fill('#password','ChangeMe!123');await p.click('button');await p.wait_for_timeout(300)
   for name in ['Overview','Projects','Experiments','Test Cases','Runs','Canaries','Invariants','Evidence','Findings','Reports','Audit Log','Settings']:
    await p.get_by_role('button',name=name).click();await p.wait_for_timeout(50);assert await p.locator('h1').inner_text()==name,(name,await p.locator('h1').inner_text())
   await p.screenshot(path='/mnt/data/muse-production/browser.png',full_page=True);await b.close()
 finally: proc.terminate();proc.wait()
 print('BROWSER UI PASS')
asyncio.run(main())
