# แหล่งอ้างอิงชุดทดสอบ Prompt Injection (Benchmark References & Citations)

เอกสารนี้รวบรวมงานวิจัยและมาตรฐานความปลอดภัยที่ใช้เป็นต้นแบบในการออกแบบเคสทดสอบใน [data/schema/test_case.schema.json](../data/schema/test_case.schema.json) และกลไกป้องกันใน [agent.py](../agent.py)

## 1. InjecAgent (ACL 2024, UIUC Kang Lab)
งานวิจัย *InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents* โดย Boyi Deng, Wenxuan Wang, Fangkai Yang และคณะ ([arXiv:2403.02691](https://arxiv.org/abs/2403.02691), [GitHub](https://github.com/uiuc-kang-lab/InjecAgent)) เสนอแนวทางวัดผลช่องโหว่ Indirect Prompt Injection ในระบบตัวแทนที่มีการเชื่อมต่อเครื่องมือ (Function Calling) โดยจำลองสถานการณ์ที่ข้อมูลภายนอกมีคำสั่งแฝงให้ตัวแทนเรียกใช้ฟังก์ชันอื่นเพื่อดึงข้อมูลความลับออกไป

ในโปรเจกต์นี้นำแนวคิดของ InjecAgent มาใช้กับเคส `IND-TH-1` และ `IND-EN-1` รวมถึงการแยกบันทึกสถานะการเรียกใช้เครื่องมือเป็น `granted` (เข้าถึงตารางสำเร็จ) และ `blocked` (ถูกบล็อกโดยนโยบายสิทธิ์)

## 2. BIPIA (Microsoft Research)
งานวิจัย *Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models* โดย Jindong Gu, Zhengyuan Liu และคณะ ([arXiv:2312.14197](https://arxiv.org/abs/2312.14197), [GitHub](https://github.com/microsoft/BIPIA)) ศึกษาการโจมตีแบบฝากคำสั่งแฝงไว้ในข้อมูลตารางและเนื้อหาภายนอก พร้อมชี้ให้เห็นว่าโมเดลภาษามักแยกไม่ออกว่าส่วนใดคือข้อมูลสำหรับอ่านและส่วนใดคือคำสั่งที่ต้องปฏิบัติตาม

โปรเจกต์นี้ใช้แนวทางจาก BIPIA ในการฝังคำสั่งแฝงลงในตาราง `research_projects` (รหัสโครงการ `RP998` และ `RP999` ใน [data/university_schema.sql](../data/university_schema.sql)) และใช้เทคนิคการตีกรอบข้อมูล (`_data_boundary` และการกรองข้อความผ่าน `_sanitize_db_cell`) เพื่อลดโอกาสที่โมเดลจะรันคำสั่งที่ฝังอยู่ในเรคคอร์ด

## 3. MultiJail: Multilingual Jailbreak & Safety Benchmark
ชุดทดสอบ *MultiJail: Multilingual Jailbreak and Safety Benchmark across High, Medium, and Low-Resource Languages* ([Hugging Face Dataset](https://huggingface.co/datasets/Necent/llm-jailbreak-prompt-injection-dataset)) ทดสอบการหลบเลี่ยงตัวกรองความปลอดภัยของโมเดลผ่านภาษาต่าง ๆ โดยพบว่าภาษาที่มีทรัพยากรระดับกลางอย่างภาษาไทย หรือการใช้ภาษาไทยปนอังกฤษ มักผ่านการฝึกด้านความปลอดภัยน้อยกว่าภาษาอังกฤษล้วน

โปรเจกต์นี้ออกแบบชุดทดสอบเปรียบเทียบ 3 รูปแบบภาษา (Thai, English, Mixed) และจำลองการสวมบทบาทงานทะเบียนหรือการตรวจสอบข้อมูลบุคลากรใน `PREBUILT_INJECTIONS` ของ [agent.py](../agent.py)

## 4. OWASP Top 10 for LLM Applications (2025)
มาตรฐานความปลอดภัยสากล [OWASP Top 10 for Large Language Model Applications (2025 Version)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) ถูกนำมาใช้เป็นแกนหลักในการจัดหมวดหมู่ภัยคุกคาม (`owasp_category`):

* **OWASP-LLM01: Prompt Injection**: การบิดเบือนหรือแทรกแซงการประมวลผลคำสั่ง ทั้งทางตรง (Direct Injection) ผ่านพรอมต์ของผู้ใช้ และทางอ้อม (Indirect Injection) ผ่านข้อมูลภายนอก/ฐานข้อมูล
* **OWASP-LLM02: Sensitive Information Disclosure**: การรั่วไหลของข้อมูลความลับ ข้อมูลส่วนบุคคล (PDPA/PII) และ Canary Tokens ผ่านการตอบกลับของโมเดล
* **OWASP-LLM06: Excessive Agency**: การให้อำนาจและสิทธิ์การเรียกใช้เครื่องมือ (Tool Execution) เกินขอบเขตของบทบาทผู้ใช้งาน (Privilege Escalation / ACL Violation)

โครงสร้างระดับการป้องกันของโปรเจกต์ (`off`, `prompt`, `tools`, `all`, `spotlight`) ออกแบบตามแนวทาง Defense-in-Depth ของ OWASP เพื่อประเมินประสิทธิภาพการลดความเสี่ยงอย่างเป็นรูปธรรม

## 5. Spotlighting (Microsoft Research, 2024)
งานวิจัย *Defending Against Indirect Prompt Injection Attacks With Spotlighting* โดย Keegan Hines, Gary Lopez, Matthew Hall, Federico Zarfati, Roshan Ramprasad, และ Blake Bullwinkel ([arXiv:2403.14720](https://arxiv.org/abs/2403.14720)) เสนอแนวทางการแยกข้อมูลที่ไม่ได้ผ่านการรับรอง (Untrusted Data) ออกจากคำสั่งประมวลผลของโมเดล โดยการสุ่มค่า Delimiter ที่ไม่ซ้ำกันในแต่ละคำขอ พร้อมกับการตีกรอบบริบทข้อมูล (Context Framing) เพื่อกำกับให้โมเดลประมวลผลข้อความภายในขอบเขตดังกล่าวเป็นข้อมูลอ้างอิงเท่านั้น (Passive Data) และไม่ปฏิบัติตามคำสั่งใด ๆ ที่แฝงอยู่

โปรเจกต์นี้นำเทคนิค Spotlighting มาพัฒนาเป็นระดับการป้องกัน `spotlight` (Isolated Spotlighting Tier) ใน [core/defenses/spotlight.py](../core/defenses/spotlight.py) และ [agent.py](../agent.py) โดยใช้ PRNG แบบกำหนด seed เพื่อการทำซ้ำผลลัพธ์ พร้อมกลไกตรวจจับและลบล้างค่า Delimiter ที่ชนกัน (Collision Neutralization) เพื่อทดสอบการป้องกันต่อ Indirect Injection อย่างเป็นระบบ
