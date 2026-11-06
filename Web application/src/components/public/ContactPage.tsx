import React, { useState } from 'react';
import { Mail, Send, AlertCircle, Info, CheckCircle2 } from 'lucide-react';
import { Button } from '../common/Button';

export const ContactPage: React.FC = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: '',
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitted, setSubmitted] = useState(false);

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!formData.name.trim()) newErrors.name = 'Full name is required.';
    if (!formData.email.trim()) {
      newErrors.email = 'Email address is required.';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      newErrors.email = 'Please enter a valid email address.';
    }
    if (!formData.subject.trim()) newErrors.subject = 'Subject is required.';
    if (!formData.message.trim()) {
      newErrors.message = 'Message content is required.';
    } else if (formData.message.trim().length < 15) {
      newErrors.message = 'Message must be at least 15 characters.';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validate()) {
      setSubmitted(true);
    }
  };

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 py-12 space-y-8 font-sans">
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/90 dark:bg-purple-950/60 border border-purple-200/90 dark:border-purple-500/40 text-xs font-mono font-medium text-purple-700 dark:text-cyan-400 shadow-xs">
          <Mail className="w-3.5 h-3.5" />
          <span>CONTACT & INQUIRIES</span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-slate-100 font-heading">
          Technical Inquiries & Feedback
        </h1>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 max-w-md mx-auto">
          Submit architecture inquiries, deployment feedback, or security evaluations.
        </p>
      </div>

      {/* Integration Notice Disclaimer */}
      <div className="p-4 bg-amber-50/70 dark:bg-[#1a1424] border border-amber-200/90 dark:border-amber-900/60 rounded-xl text-xs space-y-1.5">
        <div className="flex items-center gap-2 font-mono text-amber-800 dark:text-amber-400 font-bold text-[11px]">
          <Info className="w-4 h-4" />
          <span>BACKEND INTEGRATION BOUNDARY NOTICE</span>
        </div>
        <p className="text-amber-900/80 dark:text-amber-300/80 text-[11px] leading-relaxed">
          In this client prototype, <strong>no external SMTP or email relay is configured</strong>. Submissions validate all required inputs locally. In production, this form routes to an authorized API gateway with spam defenses.
        </p>
      </div>

      {submitted ? (
        <div className="p-8 bg-white dark:bg-[#090d24]/90 border border-emerald-300 dark:border-emerald-800 rounded-2xl text-center space-y-3 shadow-sm backdrop-blur-sm">
          <CheckCircle2 className="w-8 h-8 text-emerald-600 dark:text-emerald-400 mx-auto" />
          <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 font-heading">
            Form Input Validated Locally
          </h3>
          <p className="text-xs text-slate-600 dark:text-slate-300 max-w-md mx-auto leading-relaxed">
            Thank you, <strong className="text-slate-900 dark:text-slate-100">{formData.name}</strong>. Your message regarding <em>&quot;{formData.subject}&quot;</em> passed all client-side validation checks. As documented above, real SMTP dispatch will take place once an email gateway is configured.
          </p>
          <div className="pt-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setSubmitted(false);
                setFormData({ name: '', email: '', subject: '', message: '' });
              }}
            >
              Submit Another Inquiry
            </Button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="p-6 sm:p-8 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_24px_rgba(15,23,42,0.05)] dark:shadow-[0_0_30px_rgba(139,92,246,0.1)] space-y-4 backdrop-blur-sm">
          {/* Name */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Full Name <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="e.g. Alex Mercer"
              className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
            />
            {errors.name && <p className="text-[11px] text-rose-500 mt-1">{errors.name}</p>}
          </div>

          {/* Email */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Work / Security Contact Email <span className="text-rose-500">*</span>
            </label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              placeholder="e.g. alex.mercer@organization.internal"
              className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
            />
            {errors.email && <p className="text-[11px] text-rose-500 mt-1">{errors.email}</p>}
          </div>

          {/* Subject */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Subject <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              value={formData.subject}
              onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
              placeholder="e.g. Detection Rule Integration Inquiry"
              className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
            />
            {errors.subject && <p className="text-[11px] text-rose-500 mt-1">{errors.subject}</p>}
          </div>

          {/* Message */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Inquiry / Technical Feedback <span className="text-rose-500">*</span>
            </label>
            <textarea
              rows={4}
              value={formData.message}
              onChange={(e) => setFormData({ ...formData, message: e.target.value })}
              placeholder="Describe your inquiry, telemetry integration request, or feedback..."
              className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
            />
            {errors.message && <p className="text-[11px] text-rose-500 mt-1">{errors.message}</p>}
          </div>

          <div className="pt-2 flex justify-end">
            <button
              type="submit"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition cursor-pointer"
            >
              <span>Submit Inquiry</span>
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
