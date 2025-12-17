document.addEventListener('DOMContentLoaded', () => {
    // 1. Lấy các phần tử DOM
    const heroSection = document.getElementById('hero-section');
    const loadingOverlay = document.getElementById('loading-overlay');
    const resultSection = document.getElementById('result-section');
    
    const scanForm = document.getElementById('scan-form');
    const searchInput = document.getElementById('search-input');
    const terminalLogs = document.getElementById('terminal-logs');

    // 2. Các hàm chuyển đổi giao diện (Transition)
    function showLoading() {
        heroSection.classList.add('hidden');       // Ẩn trang chủ
        resultSection.classList.add('hidden');     // Ẩn kết quả (nếu có)
        loadingOverlay.classList.remove('hidden'); // Hiện loading
        loadingOverlay.classList.add('flex');      // Đảm bảo flex layout
        
        startTerminalEffect();
    }

    function showResults(data) {
        loadingOverlay.classList.add('hidden');    // Ẩn loading
        loadingOverlay.classList.remove('flex');
        resultSection.classList.remove('hidden');  // Hiện kết quả
        
        renderDashboard(data);
    }

    // 3. Hiệu ứng chữ chạy (Terminal Effect)
    let logInterval;
    const logMessages = [
        "Initializing handshake...",
        "Resolving DNS target...",
        "Bypassing firewall rules...",
        "Scanning ports 80, 443, 8080...",
        "Analyzing HTTP Headers...",
        "Injecting SQL payloads...",
        "Checking for XSS vectors...",
        "Validating SSL certificates...",
        "Brute-forcing admin directories...",
        "Analyzing server response..."
    ];

    function startTerminalEffect() {
        terminalLogs.innerHTML = '';
        let index = 0;
        if (logInterval) clearInterval(logInterval);
        
        logInterval = setInterval(() => {
            if (index < logMessages.length) {
                const p = document.createElement('p');
                p.className = "text-green-500 font-mono text-xs";
                p.innerHTML = `>> ${logMessages[index]}`;
                terminalLogs.appendChild(p);
                terminalLogs.scrollTop = terminalLogs.scrollHeight;
                index++;
            } else {
                index = 0;
            }
        }, 800);
    }

    // 4. HÀM XỬ LÝ DỮ LIỆU TỪ SERVER.PY
    function renderDashboard(data) {
        // A. Cập nhật thông tin cơ bản
        document.getElementById('target-url-display').textContent = data.url;
        
        // Format thời gian
        const scanTime = data.summary.scan_timestamp ? new Date(data.summary.scan_timestamp).toLocaleString('vi-VN') : new Date().toLocaleString('vi-VN');
        document.getElementById('scan-time').textContent = scanTime;

        // B. Gộp tất cả lỗ hổng từ 3 nhóm lại thành 1 danh sách
        let allVulns = [];
        if (data.results.static_holes?.vulnerabilities) {
            allVulns = allVulns.concat(data.results.static_holes.vulnerabilities);
        }
        if (data.results.dynamic_holes?.vulnerabilities) {
            allVulns = allVulns.concat(data.results.dynamic_holes.vulnerabilities);
        }
        if (data.results.abusaly_holes?.vulnerabilities) {
            allVulns = allVulns.concat(data.results.abusaly_holes.vulnerabilities);
        }

        // C. Phân loại và Đếm số lượng (Logic hiển thị màu sắc)
        let highCount = 0;
        let medCount = 0;
        let lowCount = 0;

        const tableBody = document.getElementById('vuln-table-body');
        tableBody.innerHTML = ''; // Xóa bảng cũ

        if (allVulns.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="3" class="p-8 text-center text-slate-500">Không tìm thấy lỗ hổng nào. Hệ thống an toàn!</td></tr>`;
        }

        allVulns.forEach(vuln => {
            let severity = "THẤP";
            let cssClass = "bg-blue-500/10 text-blue-400 border-blue-500/20"; // Mặc định Thấp
            
            // Logic tự động nhận diện mức độ dựa trên tên lỗi
            const cat = (vuln.category || "").toLowerCase();
            const desc = (vuln.description || "").toLowerCase();

            // Các lỗi nguy hiểm (High)
            if (cat.includes("sql") || cat.includes("xss") || cat.includes("injection") || 
                cat.includes("execution") || cat.includes("upload") || cat.includes("broken")) {
                severity = "CAO";
                cssClass = "bg-neon-red/10 text-neon-red border-neon-red/20 shadow-glow-red";
                highCount++;
            } 
            // Các lỗi trung bình (Medium)
            else if (cat.includes("disclosure") || cat.includes("config") || cat.includes("missing") || 
                     cat.includes("directory") || cat.includes("header")) {
                severity = "TB";
                cssClass = "bg-neon-yellow/10 text-neon-yellow border-neon-yellow/20";
                medCount++;
            } 
            else {
                lowCount++;
            }

            // Tạo dòng HTML cho bảng
            const row = `
                <tr class="hover:bg-white/5 transition-colors border-b border-slate-800 last:border-0">
                    <td class="p-4 align-top w-32">
                        <span class="inline-flex items-center justify-center px-2.5 py-1 rounded border text-xs font-bold w-16 ${cssClass}">
                            ${severity}
                        </span>
                    </td>
                    <td class="p-4 align-top font-bold text-white">
                        ${vuln.category}
                    </td>
                    <td class="p-4 align-top text-slate-300 font-mono text-sm break-all">
                        ${vuln.description || vuln.url || "Không có chi tiết"}
                    </td>
                </tr>
            `;
            tableBody.innerHTML += row;
        });

        // D. Cập nhật các con số thống kê trên Dashboard
        document.getElementById('total-vulns').textContent = allVulns.length;
        document.getElementById('high-vulns').textContent = highCount;
        document.getElementById('medium-vulns').textContent = medCount;

        // E. Tính điểm xếp hạng (Score) dựa trên Risk Level từ Server
        const riskLevel = data.summary.risk_level; // CRITICAL, HIGH, MEDIUM, LOW
        const scoreEl = document.getElementById('security-score');
        const riskTextEl = scoreEl.nextElementSibling; // Thẻ <p> bên dưới điểm số

        let scoreLetter = "A";
        let scoreColorClass = "text-green-500"; // Mặc định an toàn
        let riskLabel = "An toàn";

        if (riskLevel === "CRITICAL" || highCount > 2) {
            scoreLetter = "F";
            scoreColorClass = "text-neon-red drop-shadow-[0_0_10px_rgba(255,51,51,0.8)]";
            riskLabel = "NGUY HIỂM";
        } else if (riskLevel === "HIGH" || highCount > 0) {
            scoreLetter = "D";
            scoreColorClass = "text-neon-red";
            riskLabel = "Rủi ro Cao";
        } else if (riskLevel === "MEDIUM" || medCount > 0) {
            scoreLetter = "C";
            scoreColorClass = "text-neon-yellow";
            riskLabel = "Cảnh báo";
        } else {
            scoreLetter = "A";
            scoreColorClass = "text-blue-400";
            riskLabel = "Rủi ro Thấp";
        }

        scoreEl.textContent = scoreLetter;
        scoreEl.className = `text-6xl font-black ${scoreColorClass}`;
        
        riskTextEl.textContent = riskLabel;
        // Đổi màu chữ risk label theo màu điểm số (lấy class màu đầu tiên)
        riskTextEl.className = `mt-4 font-bold uppercase tracking-wide ${scoreColorClass.split(' ')[0]}`;
    }

    // 5. Sự kiện Submit Form
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = searchInput.value.trim();
        if (!url) return;

        showLoading();

        try {
            // Lưu ý: Đảm bảo đường dẫn này đúng với server.py của bạn
            const response = await fetch('/api/task', { 
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    url: url,
                    scan_types: ["static", "dynamic", "abusaly"] // Gửi tùy chọn quét mặc định
                })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || `Server Error: ${response.status}`);
            }

            const data = await response.json();
            
            // Giả lập delay 1 xíu để người dùng kịp nhìn thấy hiệu ứng "Hack xong"
            setTimeout(() => {
                showResults(data);
            }, 800);

        } catch (error) {
            console.error(error);
            alert("Lỗi: " + error.message);
            window.location.reload();
        }
    });
});