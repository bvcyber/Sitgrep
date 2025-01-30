function toggleMenu(){
    const menuOptions = document.getElementById('sidebar-options');
    const menuTitle = document.getElementById('menu-title');
    if (menuOptions.style.display === 'none' || menuOptions.style.display === '') {
        menuOptions.style.display = 'flex'; 
        menuTitle.style.display = '';
        document.getElementById("mySidebar").style.width = "181px";
        document.getElementById('logo').src = "./static/img/sitgrep-logo-full.png"
    } else {
        menuOptions.style.display = 'none'; 
        menuTitle.style.display = 'none';
        document.getElementById("mySidebar").style.width = "auto";
        document.getElementById('logo').src = "./static/img/sitgrep-logo.png"
        
    }
}