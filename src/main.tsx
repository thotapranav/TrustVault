import { Component, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
// Any render error shows a message instead of a blank white page.
class Boundary extends Component<{ children: ReactNode }, { e?: Error }> {
  state: { e?: Error } = {};
  static getDerivedStateFromError(e: Error) { return { e }; }
  render() { return this.state.e ? <div className="wrap"><div className="card"><h2>Something went wrong</h2><p className="err">{this.state.e.message}</p></div></div> : this.props.children; }
}
createRoot(document.getElementById("root")!).render(<Boundary><App /></Boundary>);
