import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from utils import parse_log_to_df, detect_bruteforce_windows
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from pathlib import Path

try:
    FONT_DIR = Path(__file__).parent
except NameError:
    FONT_DIR = Path('.')

pdfmetrics.registerFont(TTFont('DejaVu', str(FONT_DIR / 'DejaVuSans.ttf')))
pdfmetrics.registerFont(TTFont('DejaVu-Bold', str(FONT_DIR / 'DejaVuSans-Bold.ttf')))


def create_pdf_report(df_full, counts, top_fail, suspicious_list, plot_fig, window_minutes, threshold):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []

    heading_style = ParagraphStyle(
        name='Heading',
        parent=styles['Heading1'],
        fontName='DejaVu-Bold',
        fontSize=18,
        spaceAfter=12,
        alignment=1
    )
    normal_style = ParagraphStyle(
        name='Normal',
        parent=styles['Normal'],
        fontName='DejaVu',
        fontSize=10,
        spaceAfter=6
    )
    bold_style = ParagraphStyle(
        name='Bold',
        parent=styles['Normal'],
        fontName='DejaVu-Bold',
        fontSize=12,
        spaceAfter=6
    )

    Story.append(Paragraph("Báo cáo phân tích Login", heading_style))
    Story.append(Paragraph(f"Thời gian tạo báo cáo: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("<b>1. Tổng quan & Cấu hình</b>", bold_style))
    Story.append(Paragraph(f"- Tổng số bản ghi đã phân tích: {len(df_full)}", normal_style))
    Story.append(Paragraph(f"- Window Brute-force: {window_minutes} phút", normal_style))
    Story.append(Paragraph(f"- Ngưỡng thất bại: {threshold} lần", normal_style))
    Story.append(Spacer(1, 6))
    
    data_counts = [
        [Paragraph("<b>Trạng thái</b>", bold_style), Paragraph("<b>Số lượng</b>", bold_style)]
    ]
    for index, row in counts.iterrows():
        data_counts.append([row['status'], str(row['counts'])])

    table_counts = Table(data_counts, colWidths=[100, 100])
    table_counts.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'DejaVu'),
        ('FONTNAME', (0, 0), (-1, 0), 'DejaVu-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
    ]))
    Story.append(table_counts)
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("<b>2. Top IPs có nhiều login thất bại</b>", bold_style))
    
    data_top_fail = [
        [Paragraph("<b>Địa chỉ IP</b>", bold_style), Paragraph("<b>Số lần thất bại</b>", bold_style)]
    ]
    for index, row in top_fail.iterrows():
        data_top_fail.append([row['ip'], str(row['fail_count'])])
        
    table_top_fail = Table(data_top_fail, colWidths=[100, 100])
    table_top_fail.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'DejaVu'),
        ('FONTNAME', (0, 0), (-1, 0), 'DejaVu-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
    ]))
    Story.append(table_top_fail)
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("<b>3. IP nghi ngờ (Brute-force Windows)</b>", bold_style))

    if suspicious_list:
        suspicious_df = pd.DataFrame(suspicious_list)
        
        col_map = {
            'ip': 'IP',
            'start_time': 'Thời gian bắt đầu',
            'end_time': 'Thời gian kết thúc',
            'fail_count': 'Số lần'
        }
        
        # Chỉ sử dụng các cột có tồn tại trong DataFrame
        cols_to_use = {k: v for k, v in col_map.items() if k in suspicious_df.columns}

        if not cols_to_use:
            Story.append(Paragraph("Dữ liệu nghi ngờ bị thiếu các cột cần thiết.", normal_style))
        else:
            table_headers = [Paragraph(f"<b>{header}</b>", bold_style) for header in cols_to_use.values()]
            data_suspicious = [table_headers]
            
            col_widths = [80 if col == 'ip' else 120 if col in ['start_time', 'end_time'] else 80 for col in cols_to_use.keys()]
            
            for index, row in suspicious_df.iterrows():
                row_data = []
                for col in cols_to_use.keys():
                    value = row.get(col) 
                    
                    if value is None or pd.isna(value):
                        row_data.append("N/A")
                        continue
                        
                    if col in ['start_time', 'end_time']:
                        try:
                            value = pd.to_datetime(value).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            value = "LỖI DỮ LIỆU"
                    
                    row_data.append(str(value))
                
                data_suspicious.append(row_data)
            
            table_suspicious = Table(data_suspicious, colWidths=col_widths)
            table_suspicious.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, -1), 'DejaVu'),
                ('FONTNAME', (0, 0), (-1, 0), 'DejaVu-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            Story.append(table_suspicious)
            
    else:
        Story.append(Paragraph("Không phát hiện IP vượt ngưỡng.", normal_style))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("<b>4. Biểu đồ</b>", bold_style))
    
    plot_buffer = BytesIO()
    plot_fig.savefig(plot_buffer, format='png')
    plot_buffer.seek(0)
    
    img = Image(plot_buffer, width=450, height=135)
    Story.append(img)
    
    doc.build(Story)
    return buffer.getvalue()

st.set_page_config(page_title="Login Analyzer", layout="wide")

st.title("Login Analyzer — Phát hiện brute-force & hành vi bất thường")
st.caption("Upload file log (auth.log, access.log, .txt). Ứng dụng hỗ trợ mẫu auth.log/SSH và access log cơ bản.")

uploaded_file = st.file_uploader("Chọn file log (text)", type=["log","txt"])

st.sidebar.header("Cấu hình phân tích")
window_minutes = st.sidebar.number_input("Window (phút) để tính brute-force", min_value=1, max_value=60, value=5)
threshold = st.sidebar.number_input("Ngưỡng số lần thất bại trong window để cảnh báo", min_value=1, max_value=1000, value=10)

if uploaded_file is not None:
    raw = uploaded_file.read().decode("utf-8", errors="ignore")
    st.subheader("Preview (10 dòng đầu)")
    st.code("\n".join(raw.splitlines()[:10]))

    df = parse_log_to_df(raw)

    if df.empty:
        st.warning("Không tìm thấy bản ghi hợp lệ trong file.")
    else:
        st.success(f"Đã parse được {len(df)} bản ghi.")

        counts = df['status'].value_counts().rename_axis('status').reset_index(name='counts')
        st.markdown("### Thống kê chung")
        st.table(counts)
        st.download_button(
            label="Tải xuống Thống kê chung (CSV)",
            data=counts.to_csv(index=False).encode('utf-8'),
            file_name="general_stats.csv",
            mime='text/csv'
        )

        fail_df = df[df['status']=='FAIL']
        top_fail = fail_df.groupby('ip').size().sort_values(ascending=False).head(10).reset_index(name='fail_count')
        st.markdown("### Top IPs có nhiều login thất bại")
        st.table(top_fail)
        st.download_button(
            label="Tải xuống Top IPs (CSV)",
            data=top_fail.to_csv(index=False).encode('utf-8'),
            file_name="top_failed_ips.csv",
            mime='text/csv'
        )

        suspicious = detect_bruteforce_windows(fail_df, window_minutes=window_minutes, threshold=threshold)
        st.markdown("### IP nghi ngờ (brute-force windows)")
        if suspicious:
            suspicious_df = pd.DataFrame(suspicious)
            st.table(suspicious_df)
            st.download_button(
                label="Tải xuống IP nghi ngờ (CSV)",
                data=suspicious_df.to_csv(index=False).encode('utf-8'),
                file_name="suspicious_ips.csv",
                mime='text/csv'
            )
        else:
            st.info("Không phát hiện IP vượt ngưỡng.")

        ts = fail_df.set_index('timestamp').resample('1T').size()
        st.markdown("### Số lần login thất bại theo thời gian")
        fig, ax = plt.subplots(figsize=(10,3))
        ax.plot(ts.index, ts.values)
        ax.set_xlabel('Time')
        ax.set_ylabel('Failed attempts per minute')
        ax.set_title('Failed logins over time')
        st.pyplot(fig)

        st.markdown("---")
        st.subheader("Xuất báo cáo tổng hợp")
        
        pdf_bytes = create_pdf_report(
            df, 
            counts, 
            top_fail, 
            suspicious, 
            fig,
            window_minutes,
            threshold
        )
        
        st.download_button(
            label="Xuất báo cáo ĐẦY ĐỦ (PDF)",
            data=pdf_bytes,
            file_name="login_analyzer_report.pdf",
            mime="application/pdf"
        )
else:
    st.info("Upload file log để bắt đầu phân tích.")