// document.addEventListener("DOMContentLoaded", () => {
//     const searchInput = document.getElementById("searchInput");
//     const tableRows = document.querySelectorAll("tbody tr");

//     if (searchInput) {
//         searchInput.addEventListener("input", function () {
//             const query = this.value.toLowerCase();

//             tableRows.forEach(row => {
//                 const id = row.children[0].textContent.toLowerCase();
//                 const desc = row.children[1].textContent.toLowerCase();
//                 const severity = row.children[2].textContent.toLowerCase();

//                 if (id.includes(query) || desc.includes(query) || severity.includes(query)) {
//                     row.style.display = "";
//                 } else {
//                     row.style.display = "none";
//                 }
//             });
//         });
//     }
// });
