import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
from datetime import datetime, timedelta
import threading

class User:
    def __init__(self, username, password, email, phone):
        self.username = username
        self.password = password
        self.email = email
        self.phone = phone
        self.is_authenticated = False
        self.otp_code = None
        self.otp_expiry = None
        self.login_attempts = 0

class TwoFactorAuth:
    def __init__(self):
        self.users = {}
        self.otp_length = 6
        self.otp_validity = 5  # 분 단위
        
    def register_user(self, username, password, email, phone):
        """사용자 등록"""
        if not username or not password or not email or not phone:
            return False, "모든 필드를 입력해주세요."
        
        if username in self.users:
            return False, f"'{username}'은(는) 이미 존재합니다."
        
        self.users[username] = User(username, password, email, phone)
        return True, f"'{username}' 사용자가 등록되었습니다."
    
    def generate_otp(self):
        """6자리 OTP 코드 생성"""
        return ''.join(random.choices(string.digits, k=self.otp_length))
    
    def send_email_otp(self, user):
        """이메일로 OTP 발송"""
        otp = self.generate_otp()
        user.otp_code = otp
        user.otp_expiry = datetime.now() + timedelta(minutes=self.otp_validity)
        
        message = f"📧 이메일 발송\n\n"
        message += f"받는사람: {user.email}\n"
        message += f"제목: [보안] 2단계 인증 코드입니다.\n"
        message += f"내용: 인증 코드는 [{otp}]입니다.\n"
        message += f"유효시간: {self.otp_validity}분"
        
        return message
    
    def send_sms_otp(self, user):
        """SMS로 OTP 발송"""
        otp = self.generate_otp()
        user.otp_code = otp
        user.otp_expiry = datetime.now() + timedelta(minutes=self.otp_validity)
        
        message = f"📱 SMS 발송\n\n"
        message += f"받는사람: {user.phone}\n"
        message += f"내용: [보안] 인증 코드: {otp} ({self.otp_validity}분 유효)"
        
        return message
    
    def login(self, username, password, auth_method='email'):
        """1단계: 사용자명과 비밀번호로 로그인"""
        if username not in self.users:
            return False, "사용자를 찾을 수 없습니다."
        
        user = self.users[username]
        
        if user.password != password:
            return False, "비밀번호가 일치하지 않습니다."
        
        # OTP 발송
        if auth_method == 'email':
            message = self.send_email_otp(user)
        elif auth_method == 'sms':
            message = self.send_sms_otp(user)
        else:
            return False, "지원하지 않는 인증 방식입니다."
        
        return True, message
    
    def verify_otp(self, username, otp_input):
        """2단계: OTP 코드 검증"""
        if username not in self.users:
            return False, "사용자를 찾을 수 없습니다."
        
        user = self.users[username]
        
        if user.otp_code is None:
            return False, "먼저 로그인을 진행해주세요."
        
        if datetime.now() > user.otp_expiry:
            user.otp_code = None
            return False, "OTP 코드가 만료되었습니다."
        
        if user.otp_code != otp_input:
            user.login_attempts += 1
            if user.login_attempts >= 3:
                user.otp_code = None
                return False, "3회 이상 오류. 다시 로그인해주세요."
            return False, f"OTP 코드가 일치하지 않습니다. ({user.login_attempts}/3)"
        
        user.is_authenticated = True
        user.otp_code = None
        user.otp_expiry = None
        user.login_attempts = 0
        
        return True, f"✅ {username} 사용자로 로그인되었습니다."

class TwoFactorAuthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("2FA(2단계 인증) 시뮬레이터")
        self.root.geometry("700x750")
        self.root.configure(bg='#f0f0f0')
        self.root.resizable(False, False)
        
        self.auth = TwoFactorAuth()
        self.current_user = None
        self.current_otp = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """GUI 설정"""
        # 헤더
        header = tk.Frame(self.root, bg='#2c3e50', height=70)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        title = tk.Label(header, text="2FA(2단계 인증) 시뮬레이터", 
                        font=('Arial', 20, 'bold'), bg='#2c3e50', fg='white')
        title.pack(pady=15)
        
        # 노트북 (탭)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # 탭 1: 회원가입
        self.register_tab = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.register_tab, text="회원가입")
        self.setup_register_tab()
        
        # 탭 2: 로그인
        self.login_tab = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.login_tab, text="로그인")
        self.setup_login_tab()
        
        # 탭 3: 사용자 관리
        self.manage_tab = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.manage_tab, text="사용자 관리")
        self.setup_manage_tab()
    
    def setup_register_tab(self):
        """회원가입 탭 설정"""
        frame = tk.Frame(self.register_tab, bg='white', relief=tk.SUNKEN, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 사용자명
        tk.Label(frame, text="사용자명:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        self.reg_username = tk.Entry(frame, font=('Arial', 10), width=30)
        self.reg_username.pack(fill=tk.X, pady=(0, 10))
        
        # 비밀번호
        tk.Label(frame, text="비밀번호:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        self.reg_password = tk.Entry(frame, font=('Arial', 10), width=30, show='*')
        self.reg_password.pack(fill=tk.X, pady=(0, 10))
        
        # 이메일
        tk.Label(frame, text="이메일:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        self.reg_email = tk.Entry(frame, font=('Arial', 10), width=30)
        self.reg_email.pack(fill=tk.X, pady=(0, 10))
        
        # 전화번호
        tk.Label(frame, text="전화번호:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        self.reg_phone = tk.Entry(frame, font=('Arial', 10), width=30)
        self.reg_phone.pack(fill=tk.X, pady=(0, 15))
        
        # 버튼
        button_frame = tk.Frame(frame, bg='white')
        button_frame.pack(fill=tk.X)
        
        tk.Button(button_frame, text="회원가입", font=('Arial', 10, 'bold'),
                 bg='#27ae60', fg='white', padx=20, pady=8,
                 command=self.register).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="초기화", font=('Arial', 10, 'bold'),
                 bg='#95a5a6', fg='white', padx=20, pady=8,
                 command=self.clear_register).pack(side=tk.LEFT, padx=5)
        
        # 결과 메시지
        self.reg_message = tk.Label(frame, text="", font=('Arial', 9), 
                                    bg='white', fg='#27ae60', wraplength=300)
        self.reg_message.pack(fill=tk.X, pady=(15, 0))
    
    def setup_login_tab(self):
        """로그인 탭 설정"""
        frame = tk.Frame(self.login_tab, bg='white', relief=tk.SUNKEN, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 로그인 상태 표시
        self.login_status = tk.Label(frame, text="로그아웃 상태", 
                                     font=('Arial', 10, 'bold'), bg='white', fg='#e74c3c')
        self.login_status.pack(anchor='w', pady=(0, 20))
        
        # 1단계: 사용자명과 비밀번호
        step1_label = tk.Label(frame, text="1단계: 사용자명과 비밀번호", 
                              font=('Arial', 11, 'bold'), bg='white')
        step1_label.pack(anchor='w', pady=(0, 10))
        
        tk.Label(frame, text="사용자명:", font=('Arial', 9), bg='white').pack(anchor='w')
        self.login_username = tk.Entry(frame, font=('Arial', 10), width=30)
        self.login_username.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(frame, text="비밀번호:", font=('Arial', 9), bg='white').pack(anchor='w')
        self.login_password = tk.Entry(frame, font=('Arial', 10), width=30, show='*')
        self.login_password.pack(fill=tk.X, pady=(0, 10))
        
        # 인증 방식 선택
        tk.Label(frame, text="인증 방식:", font=('Arial', 9), bg='white').pack(anchor='w')
        self.auth_method = tk.StringVar(value='email')
        
        method_frame = tk.Frame(frame, bg='white')
        method_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Radiobutton(method_frame, text="이메일", variable=self.auth_method, 
                      value='email', bg='white', font=('Arial', 9)).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(method_frame, text="SMS", variable=self.auth_method, 
                      value='sms', bg='white', font=('Arial', 9)).pack(side=tk.LEFT, padx=5)
        
        # 로그인 버튼
        tk.Button(frame, text="로그인 (1단계)", font=('Arial', 10, 'bold'),
                 bg='#3498db', fg='white', padx=20, pady=8,
                 command=self.step1_login).pack(fill=tk.X, pady=(0, 20))
        
        # 구분선
        ttk.Separator(frame, orient='horizontal').pack(fill=tk.X, pady=(0, 20))
        
        # 2단계: OTP 인증
        step2_label = tk.Label(frame, text="2단계: OTP 인증", 
                              font=('Arial', 11, 'bold'), bg='white')
        step2_label.pack(anchor='w', pady=(0, 10))
        
        # OTP 메시지 표시
        self.otp_message = tk.Label(frame, text="", font=('Arial', 9), 
                                    bg='#fff3cd', fg='#856404', 
                                    wraplength=400, justify=tk.LEFT, padx=10, pady=10)
        self.otp_message.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(frame, text="OTP 코드:", font=('Arial', 9), bg='white').pack(anchor='w')
        self.otp_input = tk.Entry(frame, font=('Arial', 12, 'bold'), width=30)
        self.otp_input.pack(fill=tk.X, pady=(0, 15))
        
        # 인증 버튼
        button_frame = tk.Frame(frame, bg='white')
        button_frame.pack(fill=tk.X)
        
        tk.Button(button_frame, text="인증 (2단계)", font=('Arial', 10, 'bold'),
                 bg='#27ae60', fg='white', padx=20, pady=8,
                 command=self.step2_verify).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="로그아웃", font=('Arial', 10, 'bold'),
                 bg='#e74c3c', fg='white', padx=20, pady=8,
                 command=self.logout).pack(side=tk.LEFT, padx=5)
        
        # 결과 메시지
        self.login_message = tk.Label(frame, text="", font=('Arial', 9), 
                                      bg='white', fg='#3498db', wraplength=400)
        self.login_message.pack(fill=tk.X, pady=(15, 0))
    
    def setup_manage_tab(self):
        """사용자 관리 탭 설정"""
        frame = tk.Frame(self.manage_tab, bg='white', relief=tk.SUNKEN, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        title = tk.Label(frame, text="등록된 사용자 목록", font=('Arial', 11, 'bold'), bg='white')
        title.pack(anchor='w', pady=(0, 10))
        
        # 사용자 목록 표시
        self.user_listbox = tk.Listbox(frame, font=('Courier', 9), height=15, relief=tk.SUNKEN)
        self.user_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 새로고침 버튼
        tk.Button(frame, text="새로고침", font=('Arial', 10, 'bold'),
                 bg='#3498db', fg='white', padx=20, pady=8,
                 command=self.refresh_user_list).pack()
        
        self.refresh_user_list()
    
    def register(self):
        """회원가입 처리"""
        username = self.reg_username.get()
        password = self.reg_password.get()
        email = self.reg_email.get()
        phone = self.reg_phone.get()
        
        success, message = self.auth.register_user(username, password, email, phone)
        
        if success:
            self.reg_message.config(text=message, fg='#27ae60')
            self.clear_register()
            self.refresh_user_list()
        else:
            self.reg_message.config(text=message, fg='#e74c3c')
    
    def clear_register(self):
        """회원가입 필드 초기화"""
        self.reg_username.delete(0, tk.END)
        self.reg_password.delete(0, tk.END)
        self.reg_email.delete(0, tk.END)
        self.reg_phone.delete(0, tk.END)
        self.reg_message.config(text="")
    
    def step1_login(self):
        """1단계 로그인"""
        username = self.login_username.get()
        password = self.login_password.get()
        auth_method = self.auth_method.get()
        
        if not username or not password:
            self.login_message.config(text="사용자명과 비밀번호를 입력해주세요.", fg='#e74c3c')
            return
        
        success, message = self.auth.login(username, password, auth_method)
        
        if success:
            self.current_user = username
            self.current_otp = self.auth.users[username].otp_code
            self.login_status.config(text=f"1단계 인증 완료: {username}", fg='#f39c12')
            self.otp_message.config(text=message, bg='#d4edda', fg='#155724')
            self.login_message.config(text="OTP 코드를 입력해주세요.", fg='#27ae60')
            self.otp_input.delete(0, tk.END)
            self.otp_input.focus()
        else:
            self.login_message.config(text=message, fg='#e74c3c')
            self.login_status.config(text="로그아웃 상태", fg='#e74c3c')
    
    def step2_verify(self):
        """2단계 OTP 인증"""
        if not self.current_user:
            self.login_message.config(text="먼저 1단계 로그인을 완료해주세요.", fg='#e74c3c')
            return
        
        otp_input = self.otp_input.get()
        
        if not otp_input:
            self.login_message.config(text="OTP 코드를 입력해주세요.", fg='#e74c3c')
            return
        
        success, message = self.auth.verify_otp(self.current_user, otp_input)
        
        if success:
            self.login_status.config(text=f"✅ 로그인 완료: {self.current_user}", fg='#27ae60')
            self.login_message.config(text=message, fg='#27ae60')
            self.otp_input.delete(0, tk.END)
            self.otp_message.config(text="", bg='white')
            self.refresh_user_list()  # 사용자 목록 업데이트
        else:
            self.login_message.config(text=message, fg='#e74c3c')
    
    def logout(self):
        """로그아웃"""
        if self.current_user:
            self.auth.users[self.current_user].is_authenticated = False
            self.login_status.config(text="로그아웃 상태", fg='#e74c3c')
            self.login_message.config(text=f"✅ {self.current_user} 사용자가 로그아웃되었습니다.", fg='#27ae60')
            self.current_user = None
            self.current_otp = None
            self.otp_input.delete(0, tk.END)
            self.login_username.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
            self.otp_message.config(text="", bg='white')
            self.refresh_user_list()  # 사용자 목록 업데이트
    
    def refresh_user_list(self):
        """사용자 목록 새로고침"""
        self.user_listbox.delete(0, tk.END)
        
        if not self.auth.users:
            self.user_listbox.insert(tk.END, "등록된 사용자가 없습니다.")
        else:
            self.user_listbox.insert(tk.END, "사용자명          이메일                      전화번호")
            self.user_listbox.insert(tk.END, "-" * 60)
            
            for username, user in self.auth.users.items():
                status = "인증됨" if user.is_authenticated else "미인증"
                info = f"{username:15} {user.email:25} {user.phone:15} {status}"
                self.user_listbox.insert(tk.END, info)

if __name__ == "__main__":
    root = tk.Tk()
    app = TwoFactorAuthGUI(root)
    root.mainloop()