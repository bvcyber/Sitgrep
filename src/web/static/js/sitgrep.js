window.addEventListener("DOMContentLoaded", (event) => {
    const filters = document.getElementById('filters');
    const sortSelectElement = document.getElementById('sortSelect');
    const revertButton = document.getElementById('resetPage');
    const main = document.getElementById('main-div');
    const pageTitle = document.getElementById("page-title");

    hljs.configure({ 
        debug: false
    });
    
    main.addEventListener('click', () => {
        const menuOptions = document.getElementById('sidebar-options');
        if (menuOptions.style.display != 'none'){
            toggleMenu();
        }
        
    });

    pageTitle.addEventListener('click', () => {
        const menuOptions = document.getElementById('sidebar-options');
        if (menuOptions.style.display != 'none'){
            toggleMenu();
        }
        
    });

    document.getElementById('contentContainer').onscroll = function() {
        if (document.getElementById('contentContainer').scrollTop > 1000 || document.documentElement.scrollTop > 1000) {
            document.getElementById('scroll-to-top').style.display = 'block';
        } else {
            document.getElementById('scroll-to-top').style.display = 'none';
        }
    };
   
    sessionStorage.setItem('page', 'dashboard');
    loadDashboard();
    loadOWASPFilter();
    loadPackageFilter();
    loadRuleFilter();


    //Add an event listener for the popstate event (back/forward navigation)
    window.addEventListener("popstate", function(event) {
        // Check if the state object exists
        if (event.state) {
            window.history.replaceState(event.state, null, "");
            let token = event.state.token;
            setToken(token);
            sessionStorage.setItem("page", event.state.page)
            render();
        } 
    });

    sortSelectElement.addEventListener('change', () => {
        var selectedValue = sortSelectElement.value;
        if (selectedValue != "NA") {
            updateSort(selectedValue);
            render()
        }
    });

    if (revertButton) {
        revertButton.addEventListener('click', restoreAllFindings);
    }

    filters.addEventListener("change", () => {
        applyFilter();
        render()
    });

    scrollToTop();
});







