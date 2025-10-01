const clearInput = () => {
  const input = document.getElementsByTagName("input")[0];
  input.value = "";
}
function sendMessage() {
  const input = document.getElementsByTagName("input")[0].value;

  fetch("/link", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ message: input })
  })
  .then(response => response.json())
  .then(data => {
    // Hiển thị phản hồi từ server
    //document.getElementById("result").innerText = data.reply;

    // Hoặc tải file txt về
    const blob = new Blob([data.reply], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "result.txt";
    link.click();
  })
  .catch(error => console.error("Lỗi:", error));
}

