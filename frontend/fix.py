with open("src/App.jsx") as f:
    lines = f.readlines()
with open("src/App.jsx", "w") as f:
    for line in lines:
        if "<div className=" in line and "min-h-screen" in line:
            f.write("    <div className={'min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white'}>
")
        elif "<main className=" in line:
            f.write("      <main className={'flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8'}>
")
        elif "<footer className=" in line:
            f.write("      <footer className={'border-t border-slate-800/80 bg-slate-950/80 py-6 text-center text-xs text-slate-500'}>
")
        elif "<div className=max-w-7xl" in line:
            f.write("        <div className={'max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2'}>
")
        elif "<p className=text-slate-400" in line:
            f.write("          <p className={'text-slate-400'}>FastAPI + Scikit-learn + SHAP + React</p>
")
        else:
            f.write(line)
print("FIXED_APP_JSX")
