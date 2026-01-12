#!/usr/bin/env python3
"""
Graphical User Interface for AI Phishing Analyzer
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
from pathlib import Path
from phishing_analyzer import PhishingAnalyzer


class PhishingAnalyzerGUI:
    """GUI Application for Phishing Analyzer"""
    
    def __init__(self, root):
        """Initialize GUI"""
        self.root = root
        self.root.title("AI-Powered Phishing Analyzer")
        self.root.geometry("1000x800")
        
        # Try to set icon (optional)
        try:
            # You can add an icon file here if you have one
            pass
        except:
            pass
        
        # Initialize analyzer
        self.analyzer = None
        self.current_results = None
        
        # Create UI
        self.create_widgets()
        
        # Initialize analyzer in background
        self.initialize_analyzer()
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🛡️ AI-Powered Phishing Analyzer",
            font=('Arial', 20, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=20)
        
        # Main container
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input section
        input_frame = tk.LabelFrame(main_frame, text="Input", font=('Arial', 12, 'bold'), padx=10, pady=10)
        input_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))
        
        # Analysis type selection
        type_frame = tk.Frame(input_frame)
        type_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(type_frame, text="Analysis Type:", font=('Arial', 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.analysis_type = tk.StringVar(value="url")
        
        url_radio = tk.Radiobutton(
            type_frame,
            text="URL",
            variable=self.analysis_type,
            value="url",
            font=('Arial', 10),
            command=self.on_type_change
        )
        url_radio.pack(side=tk.LEFT, padx=5)
        
        email_radio = tk.Radiobutton(
            type_frame,
            text="Email",
            variable=self.analysis_type,
            value="email",
            font=('Arial', 10),
            command=self.on_type_change
        )
        email_radio.pack(side=tk.LEFT, padx=5)
        
        # Input field
        input_label_frame = tk.Frame(input_frame)
        input_label_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.input_label = tk.Label(input_label_frame, text="Enter URL:", font=('Arial', 10))
        self.input_label.pack(side=tk.LEFT)
        
        # File button
        self.file_button = tk.Button(
            input_label_frame,
            text="📁 Load from File",
            command=self.load_from_file,
            font=('Arial', 9)
        )
        self.file_button.pack(side=tk.RIGHT)
        
        self.input_text = scrolledtext.ScrolledText(
            input_frame,
            height=4,
            font=('Arial', 10),
            wrap=tk.WORD
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        # Options frame
        options_frame = tk.Frame(input_frame)
        options_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.use_llm_var = tk.BooleanVar(value=True)
        self.llm_check = tk.Checkbutton(
            options_frame,
            text="Use AI Analysis (LLM)",
            variable=self.use_llm_var,
            font=('Arial', 9)
        )
        self.llm_check.pack(side=tk.LEFT, padx=5)
        
        self.use_hibp_var = tk.BooleanVar(value=True)
        self.hibp_check = tk.Checkbutton(
            options_frame,
            text="Check Data Breaches (HIBP)",
            variable=self.use_hibp_var,
            font=('Arial', 9)
        )
        self.hibp_check.pack(side=tk.LEFT, padx=5)
        
        self.verbose_var = tk.BooleanVar(value=False)
        self.verbose_check = tk.Checkbutton(
            options_frame,
            text="Verbose Output",
            variable=self.verbose_var,
            font=('Arial', 9)
        )
        self.verbose_check.pack(side=tk.LEFT, padx=5)
        
        # Analyze button
        button_frame = tk.Frame(input_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.analyze_button = tk.Button(
            button_frame,
            text="🔍 ANALYZE",
            command=self.start_analysis,
            font=('Arial', 12, 'bold'),
            bg='#3498db',
            fg='white',
            padx=20,
            pady=10,
            cursor='hand2'
        )
        self.analyze_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        self.clear_button = tk.Button(
            button_frame,
            text="🗑️ Clear",
            command=self.clear_all,
            font=('Arial', 10),
            padx=20,
            pady=10
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            input_frame,
            mode='indeterminate',
            length=300
        )
        
        # Status label
        self.status_label = tk.Label(
            input_frame,
            text="Ready",
            font=('Arial', 9),
            fg='green'
        )
        self.status_label.pack(pady=(5, 0))
        
        # Results section
        results_frame = tk.LabelFrame(main_frame, text="Results", font=('Arial', 12, 'bold'), padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Risk indicator
        self.risk_frame = tk.Frame(results_frame, height=80)
        self.risk_frame.pack(fill=tk.X, pady=(0, 10))
        self.risk_frame.pack_propagate(False)
        
        self.risk_label = tk.Label(
            self.risk_frame,
            text="No Analysis Yet",
            font=('Arial', 18, 'bold'),
            bg='#ecf0f1',
            fg='#7f8c8d'
        )
        self.risk_label.pack(expand=True, fill=tk.BOTH, pady=5)
        
        # Results text
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=('Courier', 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Export button
        export_frame = tk.Frame(results_frame)
        export_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.export_button = tk.Button(
            export_frame,
            text="💾 Export Results (JSON)",
            command=self.export_results,
            font=('Arial', 10),
            state=tk.DISABLED
        )
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Status bar
        status_bar = tk.Frame(self.root, bg='#34495e', height=30)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_bar_label = tk.Label(
            status_bar,
            text="Initializing...",
            font=('Arial', 9),
            bg='#34495e',
            fg='white',
            anchor=tk.W,
            padx=10
        )
        self.status_bar_label.pack(fill=tk.X)
    
    def on_type_change(self):
        """Handle analysis type change"""
        if self.analysis_type.get() == "url":
            self.input_label.config(text="Enter URL:")
            self.input_text.delete('1.0', tk.END)
            self.input_text.insert('1.0', 'https://')
        else:
            self.input_label.config(text="Enter Email Text:")
            self.input_text.delete('1.0', tk.END)
    
    def load_from_file(self):
        """Load input from file"""
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.input_text.delete('1.0', tk.END)
                self.input_text.insert('1.0', content)
                self.update_status(f"Loaded: {Path(file_path).name}", 'green')
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
    
    def initialize_analyzer(self):
        """Initialize analyzer in background thread"""
        def init():
            try:
                self.analyzer = PhishingAnalyzer('config.yaml')
                stats = self.analyzer.get_stats()
                
                # Update status based on capabilities
                status_parts = []
                if stats['llm_available'] and stats['llm_enabled']:
                    status_parts.append("AI Ready")
                else:
                    status_parts.append("AI Disabled")
                
                if stats['hibp_enabled']:
                    status_parts.append("HIBP Enabled")
                
                status_msg = " | ".join(status_parts)
                self.root.after(0, lambda: self.update_status(f"Ready - {status_msg}", 'green'))
                
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Initialization Error: {e}", 'red'))
                self.root.after(0, lambda: messagebox.showwarning(
                    "Warning",
                    f"Analyzer initialized with errors:\n{e}\n\nSome features may not work."
                ))
        
        thread = threading.Thread(target=init, daemon=True)
        thread.start()
    
    def start_analysis(self):
        """Start analysis in background thread"""
        if not self.analyzer:
            messagebox.showerror("Error", "Analyzer not initialized")
            return
        
        input_text = self.input_text.get('1.0', tk.END).strip()
        
        if not input_text:
            messagebox.showwarning("Warning", "Please enter a URL or email text to analyze")
            return
        
        # Disable button and show progress
        self.analyze_button.config(state=tk.DISABLED)
        self.progress.pack(pady=(10, 0))
        self.progress.start(10)
        self.update_status("Analyzing...", 'blue')
        
        # Run analysis in thread
        def analyze():
            try:
                analysis_type = self.analysis_type.get()
                use_llm = self.use_llm_var.get()
                use_hibp = self.use_hibp_var.get()
                
                if analysis_type == "url":
                    results = self.analyzer.analyze_url(input_text, use_llm=use_llm)
                else:
                    results = self.analyzer.analyze_email(
                        input_text,
                        use_llm=use_llm,
                        check_hibp=use_hibp
                    )
                
                # Update UI in main thread
                self.root.after(0, lambda: self.display_results(results))
                
            except Exception as e:
                self.root.after(0, lambda: self.handle_error(e))
        
        thread = threading.Thread(target=analyze, daemon=True)
        thread.start()
    
    def display_results(self, results):
        """Display analysis results"""
        self.current_results = results
        
        # Stop progress
        self.progress.stop()
        self.progress.pack_forget()
        self.analyze_button.config(state=tk.NORMAL)
        
        # Update risk indicator
        risk_level = results.get('risk_level', 'UNKNOWN')
        risk_score = results.get('risk_score', 0)
        
        # Color mapping
        colors = {
            'LOW': ('#27ae60', 'white'),
            'MEDIUM': ('#f39c12', 'white'),
            'HIGH': ('#e74c3c', 'white'),
            'CRITICAL': ('#8e44ad', 'white'),
            'UNKNOWN': ('#95a5a6', 'white')
        }
        
        bg_color, fg_color = colors.get(risk_level, colors['UNKNOWN'])
        
        self.risk_label.config(
            text=f"{risk_level} RISK\nScore: {risk_score}/100",
            bg=bg_color,
            fg=fg_color
        )
        
        # Build results text
        results_text = self.format_results(results)
        
        # Update results display
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert('1.0', results_text)
        self.results_text.config(state=tk.DISABLED)
        
        # Enable export
        self.export_button.config(state=tk.NORMAL)
        
        # Update status
        self.update_status(f"Analysis Complete - {risk_level} Risk", 'green')
    
    def format_results(self, results):
        """Format results for display"""
        verbose = self.verbose_var.get()
        
        output = []
        output.append("=" * 70)
        output.append("PHISHING ANALYSIS RESULTS")
        output.append("=" * 70)
        output.append("")
        
        # Basic info
        analysis_type = results.get('analysis_type', 'unknown')
        output.append(f"Analysis Type: {analysis_type.upper()}")
        
        if analysis_type == 'url':
            output.append(f"URL: {results.get('input', 'N/A')}")
        elif analysis_type == 'email':
            output.append(f"Email Length: {results.get('input_length', 0)} characters")
        
        output.append("")
        
        # Risk assessment
        output.append("RISK ASSESSMENT:")
        output.append(f"  Score: {results.get('risk_score', 0)}/100")
        output.append(f"  Level: {results.get('risk_level', 'UNKNOWN')}")
        
        if results.get('overall_risk'):
            confidence = results['overall_risk'].get('confidence', 0)
            output.append(f"  Confidence: {confidence}%")
        
        output.append("")
        
        # Component scores
        if verbose and results.get('overall_risk', {}).get('component_scores'):
            output.append("COMPONENT SCORES:")
            for component, score in results['overall_risk']['component_scores'].items():
                output.append(f"  {component.upper()}: {score}/100")
            output.append("")
        
        # Threat indicators
        threat_indicators = results.get('threat_indicators', [])
        if threat_indicators:
            output.append(f"THREAT INDICATORS ({len(threat_indicators)}):")
            for i, indicator in enumerate(threat_indicators[:15], 1):
                output.append(f"  {i}. {indicator}")
            if len(threat_indicators) > 15:
                output.append(f"  ... and {len(threat_indicators) - 15} more")
            output.append("")
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            output.append("RECOMMENDATIONS:")
            for rec in recommendations:
                output.append(f"  • {rec}")
            output.append("")
        
        # LLM Analysis
        if verbose and results.get('llm_analysis', {}).get('available'):
            llm = results['llm_analysis']
            output.append("AI ANALYSIS:")
            if llm.get('summary'):
                output.append(f"  {llm['summary']}")
            if llm.get('risk_level'):
                output.append(f"  AI Assessment: {llm['risk_level']}")
            output.append("")
        
        # HIBP Results
        if results.get('hibp_results', {}).get('is_breached'):
            hibp = results['hibp_results']
            breach_count = hibp.get('breach_count', 0)
            output.append(f"DATA BREACH ALERT:")
            output.append(f"  Email found in {breach_count} breach(es)")
            if verbose and hibp.get('breaches'):
                for breach in hibp['breaches'][:5]:
                    output.append(f"  • {breach['name']} ({breach['breach_date']})")
            output.append("")
        
        # Extracted URLs
        if verbose and results.get('extracted_urls'):
            urls = results['extracted_urls']
            output.append(f"EXTRACTED URLs ({len(urls)}):")
            for url in urls[:5]:
                output.append(f"  • {url}")
            output.append("")
        
        output.append("=" * 70)
        
        return "\n".join(output)
    
    def export_results(self):
        """Export results to JSON file"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.current_results, f, indent=2, default=str)
                messagebox.showinfo("Success", f"Results exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results:\n{e}")
    
    def clear_all(self):
        """Clear all inputs and results"""
        self.input_text.delete('1.0', tk.END)
        if self.analysis_type.get() == "url":
            self.input_text.insert('1.0', 'https://')
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        self.risk_label.config(
            text="No Analysis Yet",
            bg='#ecf0f1',
            fg='#7f8c8d'
        )
        
        self.current_results = None
        self.export_button.config(state=tk.DISABLED)
        self.update_status("Ready", 'green')
    
    def handle_error(self, error):
        """Handle analysis errors"""
        self.progress.stop()
        self.progress.pack_forget()
        self.analyze_button.config(state=tk.NORMAL)
        self.update_status(f"Error: {str(error)[:50]}", 'red')
        messagebox.showerror("Analysis Error", f"An error occurred:\n\n{error}")
    
    def update_status(self, message, color='black'):
        """Update status bar"""
        color_map = {
            'green': '#27ae60',
            'red': '#e74c3c',
            'blue': '#3498db',
            'black': 'white'
        }
        self.status_bar_label.config(
            text=message,
            fg=color_map.get(color, 'white')
        )


def main():
    """Main function to run GUI"""
    root = tk.Tk()
    app = PhishingAnalyzerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
