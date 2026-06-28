# AASM Demo Lab

شبكة AI وهمية مليئة بالثغرات لاختبار أداة AASM.

---

## التشغيل السريع

### الخطوة 1 — تثبيت المتطلبات

```bash
# ثبّت AASM أولاً
cd ..
pip install -e .

# ثم ثبّت متطلبات الـ Lab
cd demo-lab
pip install -r requirements.txt
```

### الخطوة 2 — تشغيل الشبكة الوهمية

```bash
python lab_server.py
```

ستظهر هذه الرسالة:

```
╔══════════════════════════════════════════════════════════════════╗
║          AASM Demo Lab — Vulnerable AI Infrastructure            ║
╠══════════════════════════════════════════════════════════════════╣
║  🔴 Port 11434 — Ollama          (No Auth, Model Enum)          ║
║  🔴 Port 3000  — Open WebUI      (Admin Config Exposed)         ║
║  🟠 Port 4000  — LiteLLM Gateway (API Key Gen Exposed)          ║
║  🔴 Port 3001  — MCP Server      (27 Dangerous Tools, No Auth)  ║
║  🔴 Port 3002  — Flowise Agent   (Credentials Exposed)          ║
║  🟡 Port 8080  — vLLM            (Prometheus Metrics Exposed)   ║
╚══════════════════════════════════════════════════════════════════╝
```

### الخطوة 3 — شغّل AASM ضدها

افتح Terminal ثانٍ:

```bash
# الأمر الشامل
aasm scan 127.0.0.1 --ports 11434,3000,4000,3001,3002,8080

# أو شغّل السكريبت الكامل للعروض
bash demo_commands.sh
```

---

## الثغرات الموجودة في كل خدمة

| المنفذ | الخدمة | الثغرات المقصودة |
|--------|--------|-----------------|
| **11434** | Ollama | ✗ بدون مصادقة، ✗ يكشف النماذج، ✗ Prompt Injection → System Prompt Leakage |
| **3000** | Open WebUI | ✗ Admin Config مكشوف بدون Auth، ✗ قائمة المستخدمين مكشوفة، ✗ API Keys في الـ Config |
| **4000** | LiteLLM | ✗ توليد API Keys بدون صلاحية، ✗ إدارة الفرق مكشوفة، ✗ مفاتيح OpenAI/Anthropic مكشوفة |
| **3001** | MCP Server | ✗ 27 أداة خطيرة بدون Auth، ✗ `bash_execute`، ✗ `docker_run`، ✗ `get_env_vars` |
| **3002** | Flowise | ✗ Credentials endpoint مكشوف، ✗ API Keys حقيقية مكشوفة (مزيفة في الـ Demo)، ✗ أدوات تنفيذ كود |
| **8080** | vLLM | ✗ Prometheus Metrics بدون Auth، ✗ Hostname الداخلي مكشوف، ✗ بدون TLS |

---

## أوامر AASM للتجربة

```bash
# ═══════════════════════════
# اسكان الشبكة كاملة
# ═══════════════════════════
aasm scan 127.0.0.1 --ports 11434,3000,4000,3001,3002,8080

# ═══════════════════════════
# اكتشاف سريع
# ═══════════════════════════
aasm discover 127.0.0.1 --ports 11434,3000,4000,3001,3002,8080

# ═══════════════════════════
# بصمة تفصيلية لكل خدمة
# ═══════════════════════════
aasm fingerprint http://localhost:11434   # Ollama
aasm fingerprint http://localhost:3000   # Open WebUI
aasm fingerprint http://localhost:4000   # LiteLLM
aasm fingerprint http://localhost:3002   # Flowise

# ═══════════════════════════
# اكتشاف وتحليل MCP
# ═══════════════════════════
aasm mcp 127.0.0.1 --ports 3001

# ═══════════════════════════
# اختبار أمني هجومي
# ═══════════════════════════
aasm assess http://localhost:11434          # Prompt Injection
aasm assess http://localhost:11434 --jailbreak  # Jailbreak Test

# ═══════════════════════════
# تدقيق أمني شامل
# ═══════════════════════════
aasm audit http://localhost:11434   # Ollama
aasm audit http://localhost:4000   # LiteLLM
aasm audit http://localhost:3001   # MCP

# ═══════════════════════════
# تحليل AI Agents
# ═══════════════════════════
aasm agents 127.0.0.1 --ports 3002

# ═══════════════════════════
# تقارير من ملف سبق حفظه
# ═══════════════════════════
aasm risk   scan_result.json
aasm report scan_result.json --formats html,sarif
aasm graph  scan_result.json --formats dot,mermaid
```

---

## ما ستكتشفه AASM

عند تشغيل `aasm scan`:

```
🔴 CRITICAL — Ollama بدون مصادقة (يكشف 5 نماذج)
🔴 CRITICAL — MCP Server: أداة bash_execute بدون حماية
🔴 CRITICAL — MCP Server: أداة docker_run (Container Escape)
🔴 CRITICAL — MCP Server: 27 أداة خطيرة بدون Auth
🔴 CRITICAL — Flowise: Credentials مكشوفة (OpenAI + AWS + GitHub)
🔴 CRITICAL — Open WebUI: Admin Config مكشوف (يحتوي DB Password)
🔴 CRITICAL — LiteLLM: API Key Generation بدون صلاحية
🟠 HIGH    — System Prompt Disclosure في Ollama
🟠 HIGH    — مفاتيح OpenAI/Anthropic في LiteLLM Management
🟡 MEDIUM  — Prometheus Metrics مكشوفة (vLLM)
🟡 MEDIUM  — لا يوجد TLS في أي خدمة
```

**Risk Score المتوقع: 9.8/10 — CRITICAL** 🔴

---

## ملاحظة

هذه الشبكة **وهمية تماماً** ومخصصة للتعليم والتوضيح فقط.  
جميع البيانات المحتوية على مفاتيح API ومعلومات حساسة هي **بيانات وهمية** لا قيمة لها.
