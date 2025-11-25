import os

# Define the file structure and contents
files = {
    "backend/requirements.txt": """fastapi
uvicorn
sqlalchemy
pydantic
python-jose[cryptography]
passlib[bcrypt]
python-multipart""",

    "backend/server.py": """import os
import json
from datetime import datetime, timedelta
from typing import List, Optional, Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, declarative_base, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURATION ---
SECRET_KEY = "CHANGE_THIS_TO_A_LONG_RANDOM_STRING_FOR_PROD"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week login
DATABASE_URL = "sqlite:///./zenjournal.db"

# --- DATABASE SETUP ---
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- MODELS (SQLAlchemy) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())
    questions = relationship("Question", back_populates="owner")
    entries = relationship("Entry", back_populates="owner")

class Question(Base):
    __tablename__ = "questions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    text = Column(String)
    type = Column(String)  # 'text', 'scale', 'boolean'
    order = Column(Integer, default=0)
    active = Column(Boolean, default=True)
    owner = relationship("User", back_populates="questions")

class Entry(Base):
    __tablename__ = "entries"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(String, index=True) # YYYY-MM-DD
    answers_json = Column(Text) # JSON string of answers
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())
    owner = relationship("User", back_populates="entries")

Base.metadata.create_all(bind=engine)

# --- SCHEMAS (Pydantic) ---
class QuestionBase(BaseModel):
    text: str
    type: str
    active: bool

class QuestionOut(QuestionBase):
    id: int
    class Config:
        orm_mode = True

class EntryCreate(BaseModel):
    date: str
    answers: dict

class EntryOut(BaseModel):
    id: int
    date: str
    answers: dict
    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    email: str
    password: str

# --- AUTH & UTILS ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(status_code=401)
    return user

# --- APP ---
app = FastAPI(title="ZenJournal API")

# Allow CORS for development (React on 5173, FastAPI on 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ROUTES ---

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = pwd_context.hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Add default questions
    defaults = [
        Question(text="What was the highlight of today?", type="text", owner=new_user),
        Question(text="How is your energy level?", type="scale", owner=new_user),
        Question(text="One thing you learned?", type="text", owner=new_user)
    ]
    db.add_all(defaults)
    db.commit()
    
    return {"msg": "User created"}

@app.get("/questions", response_model=List[QuestionOut])
def get_questions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Question).filter(Question.user_id == current_user.id).all()

@app.post("/questions")
def add_question(question: QuestionBase, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_q = Question(**question.dict(), owner=current_user)
    db.add(new_q)
    db.commit()
    return new_q

@app.delete("/questions/{q_id}")
def delete_question(q_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Question).filter(Question.id == q_id, Question.user_id == current_user.id).first()
    if q:
        db.delete(q)
        db.commit()
    return {"msg": "Deleted"}

@app.get("/entries", response_model=List[EntryOut])
def get_entries(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    entries = db.query(Entry).filter(Entry.user_id == current_user.id).order_by(Entry.date.desc()).all()
    # Parse JSON for response
    return [{"id": e.id, "date": e.date, "answers": json.loads(e.answers_json)} for e in entries]

@app.post("/entries")
def save_entry(entry: EntryCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check if entry exists for this date
    existing = db.query(Entry).filter(Entry.user_id == current_user.id, Entry.date == entry.date).first()
    
    answers_str = json.dumps(entry.answers)
    
    if existing:
        existing.answers_json = answers_str
        db.commit()
        return {"msg": "Updated"}
    else:
        new_entry = Entry(user_id=current_user.id, date=entry.date, answers_json=answers_str)
        db.add(new_entry)
        db.commit()
        return {"msg": "Created"}
""",

    "frontend/package.json": """{
  "name": "zen-journal",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "lucide-react": "^0.300.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.43",
    "@types/react-dom": "^18.2.17",
    "@vitejs/plugin-react": "^4.2.1",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.4.0",
    "vite": "^5.0.8"
  }
}""",

    "frontend/vite.config.js": """import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/token': 'http://127.0.0.1:8000',
      '/register': 'http://127.0.0.1:8000',
      '/questions': 'http://127.0.0.1:8000',
      '/entries': 'http://127.0.0.1:8000',
    }
  }
})""",

    "frontend/index.html": """<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Zen Journal</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>""",

    "frontend/src/index.css": """@tailwind base;
@tailwind components;
@tailwind utilities;

@layer utilities {
  .animate-fade-in {
    animation: fadeIn 0.5s ease-out forwards;
  }
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}""",

    "frontend/src/main.jsx": """import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)""",

    "frontend/src/App.jsx": """import React, { useState, useEffect } from 'react';
import { 
  Book, Settings, PenLine, Calendar, ChevronRight, 
  LogOut, Plus, Trash2, Save, CheckCircle2 
} from 'lucide-react';

// --- API CLIENT ---
// Ensure this points to the right place. In Vite dev, the proxy handles it.
// In prod (same domain), a relative path or the same origin works.
const API_URL = ""; 

const api = {
  token: localStorage.getItem('token'),
  
  headers() {
    return { 
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  },

  async login(username, password) {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    const res = await fetch(`${API_URL}/token`, { method: 'POST', body: formData });
    if (!res.ok) throw new Error('Login failed');
    const data = await res.json();
    this.token = data.access_token;
    localStorage.setItem('token', data.access_token);
    return data;
  },

  async register(email, password) {
    const res = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) throw new Error('Registration failed');
    return res.json();
  },

  async getQuestions() {
    const res = await fetch(`${API_URL}/questions`, { headers: this.headers() });
    if (res.status === 401) { logout(); return []; }
    return res.json();
  },

  async addQuestion(text, type) {
    await fetch(`${API_URL}/questions`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({ text, type, active: true })
    });
  },

  async deleteQuestion(id) {
    await fetch(`${API_URL}/questions/${id}`, { method: 'DELETE', headers: this.headers() });
  },

  async getEntries() {
    const res = await fetch(`${API_URL}/entries`, { headers: this.headers() });
    return res.json();
  },

  async saveEntry(date, answers) {
    await fetch(`${API_URL}/entries`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({ date, answers })
    });
  }
};

const logout = () => {
  localStorage.removeItem('token');
  window.location.reload();
};

// --- COMPONENTS ---

const Button = ({ children, onClick, variant = 'primary', className = '', ...props }) => {
  const base = "px-6 py-3 rounded-2xl font-medium transition-all active:scale-95 flex items-center justify-center gap-2";
  const styles = {
    primary: "bg-slate-800 text-white shadow-lg shadow-slate-200 hover:bg-slate-700",
    secondary: "bg-white text-slate-600 border border-slate-200 hover:bg-slate-50",
    danger: "bg-red-50 text-red-600 border border-red-100",
    ghost: "text-slate-500 hover:bg-slate-100"
  };
  return <button onClick={onClick} className={`${base} ${styles[variant]} ${className}`} {...props}>{children}</button>;
};

const Card = ({ children, className = '' }) => (
  <div className={`bg-white/80 backdrop-blur-md border border-white/20 rounded-3xl p-6 shadow-sm ${className}`}>{children}</div>
);

// --- VIEWS ---

const LoginView = ({ onLogin }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      if (isRegister) {
        await api.register(email, password);
        await api.login(email, password); // Auto login
      } else {
        await api.login(email, password);
      }
      onLogin();
    } catch (err) {
      setError('Invalid credentials or server error');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-6">
      <Card className="w-full max-w-sm space-y-6">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-indigo-100 text-indigo-600 rounded-xl flex items-center justify-center mx-auto mb-4">
            <Book size={24} />
          </div>
          <h1 className="text-2xl font-serif text-slate-800">Zen Journal</h1>
          <p className="text-slate-500">{isRegister ? "Create your sanctuary." : "Welcome back."}</p>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <input 
            className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-indigo-100"
            placeholder="Email" 
            value={email} 
            onChange={e => setEmail(e.target.value)} 
          />
          <input 
            className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-indigo-100"
            placeholder="Password" 
            type="password" 
            value={password} 
            onChange={e => setPassword(e.target.value)} 
          />
          {error && <p className="text-red-500 text-sm text-center">{error}</p>}
          <Button className="w-full">{isRegister ? "Sign Up" : "Log In"}</Button>
        </form>
        
        <button onClick={() => setIsRegister(!isRegister)} className="w-full text-sm text-slate-400 hover:text-indigo-600">
          {isRegister ? "Already have an account? Log in" : "Need an account? Sign up"}
        </button>
      </Card>
    </div>
  );
};

const MainApp = () => {
  const [tab, setTab] = useState('write');
  const [questions, setQuestions] = useState([]);
  const [entries, setEntries] = useState([]);
  const [todayAnswers, setTodayAnswers] = useState({});
  const [loading, setLoading] = useState(true);

  const todayDate = new Date().toISOString().split('T')[0];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [qs, es] = await Promise.all([api.getQuestions(), api.getEntries()]);
      setQuestions(qs);
      setEntries(es);
      
      const todayEntry = es.find(e => e.date === todayDate);
      if (todayEntry) setTodayAnswers(todayEntry.answers);
      setLoading(false);
    } catch (e) {
      console.error(e);
      // Fallback if API fails (e.g., first load without auth)
      setLoading(false);
    }
  };

  const handleSave = async () => {
    await api.saveEntry(todayDate, todayAnswers);
    loadData(); // Refresh history
  };

  const handleAddQ = async (text) => {
    if (!text) return;
    await api.addQuestion(text, 'text');
    loadData();
  };

  if (loading) return <div className="h-screen flex items-center justify-center text-slate-400">Loading...</div>;

  return (
    <div className="max-w-md mx-auto min-h-screen flex flex-col pb-24 px-6 pt-12 relative">
       {/* Header */}
       <div className="flex justify-between items-center mb-8">
         <div>
           <h1 className="text-2xl font-serif text-slate-800 capitalize">{tab}</h1>
           <p className="text-slate-400 text-sm">{new Date().toDateString()}</p>
         </div>
         <button onClick={logout} className="text-slate-300 hover:text-slate-500"><LogOut size={20}/></button>
       </div>

       {/* WRITE TAB */}
       {tab === 'write' && (
         <div className="space-y-6 animate-fade-in">
           {questions.length === 0 && <p className="text-slate-400">No questions configured. Go to settings.</p>}
           {questions.map((q, i) => (
             <div key={q.id} className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm">
               <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                 Question {i + 1}
               </label>
               <h3 className="text-lg text-slate-800 mb-3 font-medium">{q.text}</h3>
               {q.type === 'scale' ? (
                 <input 
                   type="range" min="1" max="10" 
                   value={todayAnswers[q.id] || 5}
                   onChange={e => setTodayAnswers({...todayAnswers, [q.id]: parseInt(e.target.value)})}
                   className="w-full h-2 bg-slate-100 rounded-lg appearance-none cursor-pointer accent-slate-800"
                 />
               ) : (
                 <textarea
                   className="w-full bg-slate-50 rounded-xl p-3 text-slate-700 outline-none focus:ring-2 focus:ring-indigo-50 resize-none"
                   rows={3}
                   placeholder="Your thoughts..."
                   value={todayAnswers[q.id] || ''}
                   onChange={e => setTodayAnswers({...todayAnswers, [q.id]: e.target.value})}
                 />
               )}
             </div>
           ))}
           <Button onClick={handleSave} className="w-full mt-4">Save Entry</Button>
         </div>
       )}

       {/* HISTORY TAB */}
       {tab === 'history' && (
         <div className="space-y-4 animate-fade-in">
           {entries.length === 0 && <p className="text-center text-slate-400 mt-10">No entries yet.</p>}
           {entries.map(e => (
             <Card key={e.id} className="group hover:border-indigo-100 transition-all">
               <div className="flex justify-between mb-2">
                 <span className="font-serif font-medium text-slate-700">{e.date}</span>
                 <ChevronRight size={16} className="text-slate-300"/>
               </div>
               <div className="text-sm text-slate-500 line-clamp-2">
                 {Object.values(e.answers)[0] || "No text content..."}
               </div>
             </Card>
           ))}
         </div>
       )}

       {/* SETTINGS TAB */}
       {tab === 'settings' && (
         <div className="space-y-4 animate-fade-in">
           {questions.map(q => (
             <div key={q.id} className="flex justify-between items-center bg-white p-4 rounded-xl border border-slate-100">
               <span className="text-slate-700">{q.text}</span>
               <button onClick={() => api.deleteQuestion(q.id)} className="text-slate-300 hover:text-red-400"><Trash2 size={18}/></button>
             </div>
           ))}
           <div className="flex gap-2 mt-4">
             <input id="newQ" placeholder="New question..." className="flex-1 bg-white border border-slate-200 rounded-xl px-4" />
             <Button onClick={() => {
               const el = document.getElementById('newQ');
               handleAddQ(el.value);
               el.value = '';
             }} className="w-12"><Plus/></Button>
           </div>
         </div>
       )}

       {/* Bottom Nav */}
       <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-white/90 backdrop-blur-xl border border-white/50 shadow-2xl rounded-2xl p-2 flex gap-8 z-50">
         <NavBtn icon={<Book size={20}/>} active={tab==='history'} onClick={()=>setTab('history')} />
         <NavBtn icon={<PenLine size={24}/>} active={tab==='write'} onClick={()=>setTab('write')} primary />
         <NavBtn icon={<Settings size={20}/>} active={tab==='settings'} onClick={()=>setTab('settings')} />
       </div>
    </div>
  );
};

const NavBtn = ({ icon, active, onClick, primary }) => (
  <button onClick={onClick} className={`p-3 rounded-xl transition-all ${active ? 'text-indigo-600 bg-indigo-50' : 'text-slate-400 hover:text-slate-600'} ${primary ? 'bg-slate-800 text-white shadow-lg hover:bg-slate-700 hover:text-white' : ''}`}>
    {icon}
  </button>
);

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 selection:bg-indigo-100">
      {token ? <MainApp /> : <LoginView onLogin={() => setToken(localStorage.getItem('token'))} />}
    </div>
  );
}"""
}

def install():
    print("creating project structure...")
    for path, content in files.items():
        # Ensure directory exists
        dir_name = os.path.dirname(path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        
        # Write file
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Created {path}")

    print("\nDone! To start:")
    print("1. cd backend && pip install -r requirements.txt && uvicorn server:app --reload")
    print("2. cd frontend && npm install && npm run dev")

if __name__ == "__main__":
    install()
