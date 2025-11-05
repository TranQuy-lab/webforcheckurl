function getMessage() {
    // 1. Lấy giá trị đầu vào
    const inputElement = document.querySelector('input[type="search"]');
    const input = inputElement ? inputElement.value : '';

    if (!input) {
        alert("Vui lòng nhập thông điệp để gửi.");
        return;
    }

    // 2. Thực hiện cuộc gọi API
    fetch(`/api/task/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Gửi giá trị đầu vào trong phần thân (body)
        body: JSON.stringify({ url: input }) 
    })
    .then(response => {
        // Kiểm tra xem yêu cầu có thành công không
        if (!response.ok) {
            // Ném lỗi nếu trạng thái không phải là 2xx
            throw new Error(`Lỗi HTTP! trạng thái: ${response.status}`);
        }
        return response.json(); // Phân tích phần thân phản hồi JSON
    })
    .catch(error => {
        // Xử lý mọi lỗi trong quá trình thực hiện fetch
        const resultElement = document.getElementById('result');
        if (resultElement) {
            resultElement.textContent = `Gọi API thất bại: ${error.url || error.message}`;
        }
        console.error('Lỗi:', error);
    });
}

// Hàm để xóa đầu vào, theo gợi ý của nút trong html.html
function clearInput() {
    const inputElement = document.querySelector('input[type="search"]');
    if (inputElement) {
        inputElement.value = '';
    }
    const resultElement = document.getElementById('result');
    if (resultElement) {
        resultElement.textContent = ''; // Xóa hiển thị kết quả
    }
}