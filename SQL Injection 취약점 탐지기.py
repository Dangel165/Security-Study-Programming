import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import re

class SQLInjectionDetector:
    def __init__(self):
        self.sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
            'ALTER', 'UNION', 'EXEC', 'EXECUTE', 'SCRIPT', 'WHERE',
            'FROM', 'JOIN', 'ORDER BY', 'GROUP BY', 'HAVING'
        ]
        
        self.dangerous_patterns = [
            (r"('\s*(OR|AND)\s*')", "OR/AND 논리 연산자"),
            (r"(;.*--)", "주석을 이용한 쿼리 조작"),
            (r"(UNION\s+SELECT)", "UNION SELECT 명령"),
            (r"(DROP\s+(TABLE|DATABASE))", "DROP 명령"),
            (r"(INSERT\s+INTO)", "INSERT 명령"),
            (r"(DELETE\s+FROM)", "DELETE 명령"),
            (r"(UPDATE\s+.*\s+SET)", "UPDATE 명령"),
            (r"(EXEC|EXECUTE)", "동적 쿼리 실행"),
            (r"(<script|javascript:)", "XSS 공격 시도"),
            (r"(=\s*')", "단순 따옴표 주입"),
            (r'(--\s*$|#\s*$|\/\*)', "SQL 주석"),
            (r"(OR\s+1\s*=\s*1)", "항상 참인 조건"),
            (r"(OR\s+''\s*=\s*')", "문자열 비교 우회"),
            (r"(\bOR\b.*\bOR\b)", "OR 체이닝"),
            (r"(CASE\s+WHEN)", "CASE-WHEN 문"),
        ]
    
    def detect_injection(self, input_string):
        """SQL Injection 취약점 탐지"""
        if not input_string.strip():
            return [], 0
        
        input_upper = input_string.upper()
        vulnerabilities = []
        risk_score = 0
        
        # 패턴 매칭을 통한 탐지
        for pattern, description in self.dangerous_patterns:
            matches = re.finditer(pattern, input_string, re.IGNORECASE)
            for match in matches:
                vulnerabilities.append({
                    'type': description,
                    'content': match.group(),
                    'position': match.start(),
                    'severity': self.calculate_severity(description)
                })
                risk_score += 15
        
        # SQL 키워드 탐지
        for keyword in self.sql_keywords:
            if f" {keyword} " in f" {input_upper} " or input_upper.startswith(keyword):
                vulnerabilities.append({
                    'type': f'SQL 키워드 감지: {keyword}',
                    'content': keyword,
                    'position': input_upper.find(keyword),
                    'severity': 'HIGH' if keyword in ['DROP', 'DELETE', 'EXEC'] else 'MEDIUM'
                })
                risk_score += 10
        
        # 특수문자 개수 검사
        special_chars = len(re.findall(r"['\";\\]", input_string))
        if special_chars > 2:
            vulnerabilities.append({
                'type': '의심스러운 특수문자 집중',
                'content': f'{special_chars}개의 특수문자 발견',
                'position': 0,
                'severity': 'MEDIUM'
            })
            risk_score += 5
        
        # 중복 제거
        vulnerabilities = list({v['type']: v for v in vulnerabilities}.values())
        
        # 위험도 점수 제한
        risk_score = min(risk_score, 100)
        
        return vulnerabilities, risk_score
    
    def calculate_severity(self, description):
        """위험도 계산"""
        high_risk = ['DROP', 'DELETE', 'EXEC', 'EXECUTE', 'UNION SELECT', 'INSERT']
        medium_risk = ['SELECT', 'UPDATE', 'WHERE', 'ORDER BY']
        
        for keyword in high_risk:
            if keyword in description:
                return 'HIGH'
        
        for keyword in medium_risk:
            if keyword in description:
                return 'MEDIUM'
        
        return 'LOW'
    
    def get_recommendation(self, input_string):
        """방어 방법 제안"""
        recommendations = []
        input_upper = input_string.upper()
        
        if "'" in input_string or '"' in input_string:
            recommendations.append("✓ 입력값의 따옴표를 이스케이프 처리하세요")
            recommendations.append("✓ Prepared Statement(파라미터화 쿼리)를 사용하세요")
        
        if any(kw in input_upper for kw in ['UNION', 'SELECT', 'DROP']):
            recommendations.append("✓ 입력값 검증 및 화이트리스트 필터링을 적용하세요")
            recommendations.append("✓ 최소 권한 원칙으로 DB 사용자 권한을 제한하세요")
        
        if '--' in input_string or '#' in input_string:
            recommendations.append("✓ SQL 주석 문자(--,#,/*,*/)를 필터링하세요")
        
        if re.search(r"OR\s+['\"]?\s*=\s*['\"]", input_string, re.IGNORECASE):
            recommendations.append("✓ 입력값 형식 검증(숫자, 이메일 등)을 수행하세요")
        
        if not recommendations:
            recommendations.append("✓ 모든 사용자 입력값을 검증하세요")
            recommendations.append("✓ ORM(Object-Relational Mapping) 라이브러리 사용을 권장합니다")
        
        return recommendations

class SQLInjectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection 취약점 탐지기")
        self.root.geometry("900x800")
        self.root.configure(bg='#f0f0f0')
        
        self.detector = SQLInjectionDetector()
        
        self.setup_ui()
    
    def setup_ui(self):
        """GUI 설정"""
        # 헤더
        header = tk.Frame(self.root, bg='#2c3e50', height=60)
        header.pack(fill=tk.X)
        
        title = tk.Label(header, text="🔒 SQL Injection 취약점 탐지기", 
                        font=('Arial', 18, 'bold'), 
                        bg='#2c3e50', fg='white')
        title.pack(pady=10)
        
        # 메인 컨테이너
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # 입력 섹션
        input_label = tk.Label(main_frame, text="분석할 SQL 쿼리 입력:", 
                              font=('Arial', 11, 'bold'), bg='#f0f0f0')
        input_label.pack(anchor='w')
        
        self.input_text = scrolledtext.ScrolledText(main_frame, height=6, width=100,
                                                    font=('Arial', 10),
                                                    bg='white', relief=tk.SUNKEN)
        self.input_text.pack(fill=tk.BOTH, expand=False, pady=(5, 15))
        self.input_text.bind('<KeyRelease>', self.on_input_change)
        
        # 버튼 섹션
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill=tk.X, pady=(0, 15))
        
        analyze_btn = tk.Button(button_frame, text="🔍 분석", 
                               command=self.analyze, bg='#3498db', 
                               fg='white', font=('Arial', 10, 'bold'),
                               padx=20, pady=8)
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="🗑️ 초기화", 
                             command=self.clear, bg='#95a5a6', 
                             fg='white', font=('Arial', 10, 'bold'),
                             padx=20, pady=8)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # 위험도 표시
        risk_frame = tk.Frame(main_frame, bg='white', relief=tk.SUNKEN, padx=15, pady=10)
        risk_frame.pack(fill=tk.X, pady=(0, 15))
        
        risk_label = tk.Label(risk_frame, text="위험도:", font=('Arial', 10, 'bold'), 
                             bg='white')
        risk_label.pack(anchor='w')
        
        self.risk_bar_frame = tk.Frame(risk_frame, bg='#ecf0f1', height=25)
        self.risk_bar_frame.pack(fill=tk.X, pady=(5, 0))
        self.risk_bar_frame.pack_propagate(False)
        
        self.risk_bar = tk.Label(self.risk_bar_frame, text="0%", 
                                font=('Arial', 9, 'bold'),
                                bg='#2ecc71', fg='white', anchor='w', padx=10)
        self.risk_bar.pack(fill=tk.X, expand=True)
        
        # 결과 섹션
        result_label = tk.Label(main_frame, text="탐지 결과:", 
                               font=('Arial', 11, 'bold'), bg='#f0f0f0')
        result_label.pack(anchor='w')
        
        self.result_frame = tk.Frame(main_frame, bg='white', relief=tk.SUNKEN)
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 15))
        
        self.result_text = scrolledtext.ScrolledText(self.result_frame, height=10,
                                                     font=('Courier', 9),
                                                     bg='white', state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 권장사항 섹션
        recommendation_label = tk.Label(main_frame, text="방어 권장사항:", 
                                       font=('Arial', 11, 'bold'), bg='#f0f0f0')
        recommendation_label.pack(anchor='w')
        
        self.recommendation_text = scrolledtext.ScrolledText(main_frame, height=5,
                                                            font=('Arial', 9),
                                                            bg='#e8f5e9')
        self.recommendation_text.pack(fill=tk.BOTH, expand=False, pady=(5, 0))
        self.recommendation_text.config(state=tk.DISABLED)
    
    def on_input_change(self, event=None):
        """입력 변경 시 자동 분석"""
        self.analyze()
    
    def analyze(self):
        """취약점 분석"""
        input_string = self.input_text.get("1.0", tk.END).strip()
        
        vulnerabilities, risk_score = self.detector.detect_injection(input_string)
        recommendations = self.detector.get_recommendation(input_string)
        
        # 위험도 바 업데이트
        self.update_risk_bar(risk_score)
        
        # 결과 표시
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        
        if not input_string:
            self.result_text.insert("1.0", "분석할 입력값을 입력해주세요.")
            self.result_text.config(state=tk.DISABLED)
            return
        
        if not vulnerabilities:
            self.result_text.insert("1.0", "✅ 취약점이 탐지되지 않았습니다!\n")
        else:
            self.result_text.insert("1.0", f"⚠️  총 {len(vulnerabilities)}개의 잠재적 취약점 발견:\n\n")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                color_map = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
                color = color_map.get(vuln['severity'], '⚪')
                
                result = f"{i}. {color} [{vuln['severity']}] {vuln['type']}\n"
                result += f"   내용: {vuln['content']}\n\n"
                self.result_text.insert(tk.END, result)
        
        self.result_text.config(state=tk.DISABLED)
        
        # 권장사항 표시
        self.recommendation_text.config(state=tk.NORMAL)
        self.recommendation_text.delete("1.0", tk.END)
        
        for rec in recommendations:
            self.recommendation_text.insert(tk.END, rec + "\n")
        
        self.recommendation_text.config(state=tk.DISABLED)
    
    def update_risk_bar(self, risk_score):
        """위험도 바 업데이트"""
        width = int((risk_score / 100) * 250)
        
        if risk_score < 30:
            color = '#2ecc71'  # 초록색 (안전)
        elif risk_score < 60:
            color = '#f39c12'  # 주황색 (주의)
        else:
            color = '#e74c3c'  # 빨간색 (위험)
        
        self.risk_bar.config(text=f"{risk_score}%", bg=color)
        self.risk_bar.config(width=max(1, width))
    
    def clear(self):
        """초기화"""
        self.input_text.delete("1.0", tk.END)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.recommendation_text.config(state=tk.NORMAL)
        self.recommendation_text.delete("1.0", tk.END)
        self.recommendation_text.config(state=tk.DISABLED)
        self.risk_bar.config(text="0%", bg='#2ecc71')

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLInjectionGUI(root)
    root.mainloop()