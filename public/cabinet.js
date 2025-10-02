// переключение вкладок
document.querySelectorAll('.tabs a').forEach(tab => {
  tab.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.tabs a').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
});

// смена пароля
const passForm = document.getElementById("changePasswordForm");
if(passForm){
  passForm.addEventListener("submit", async e=>{
    e.preventDefault();
    const oldPassword = document.getElementById("oldPassword").value;
    const newPassword = document.getElementById("newPassword").value;

    const res = await fetch("/api/change-password", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({oldPassword, newPassword}),
      credentials:"include"
    });

    const msg = await res.json();
    document.getElementById("passMsg").textContent = msg.message;
  });
}

// привязка Telegram
const tgBtn = document.getElementById("linkTelegram");
if(tgBtn){
  tgBtn.addEventListener("click", ()=>{
    alert("Откроется окно Telegram для подтверждения.");
    document.getElementById("tgStatus").textContent = "Привязан ✅";
  });
}

// загрузка профиля
async function loadProfile(){
  try{
    const res = await fetch("/api/profile",{credentials:"include"});
    if(res.ok){
      const user = await res.json();
      document.getElementById("fio").textContent = user.fio;
      document.getElementById("dob").textContent = user.dob;
      document.getElementById("email").textContent = user.email;
      document.getElementById("phone").textContent = user.phone;
    }else{
      location.href="auth.html";
    }
  }catch(err){
    console.error("Ошибка загрузки профиля",err);
  }
}
loadProfile();
