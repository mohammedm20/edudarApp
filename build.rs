fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "Edudar Installer");
        res.set("FileDescription", "Official Edudar Web Installer & Bootstrapper");
        res.set("CompanyName", "Edudar");
        res.set("LegalCopyright", "Copyright (C) 2026 Edudar");
        let _ = res.compile();
    }
}
