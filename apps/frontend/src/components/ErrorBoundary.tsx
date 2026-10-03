import * as React from "react";

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

// Catches uncaught render/runtime errors anywhere in the tree below it.
// Without this, a single unguarded error (e.g. a bad API response shape)
// unmounts the entire React tree and leaves the user on a blank white page
// with no way to recover except a hard refresh.
export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("Unhandled UI error:", error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#090909] text-white flex items-center justify-center p-6 font-mono">
          <div className="max-w-md w-full bg-[#111111] border border-[#222222] rounded-lg p-8 text-center space-y-4">
            <h2 className="text-lg font-bold uppercase tracking-wider text-[#ff4040]">
              Something went wrong
            </h2>
            <p className="text-xs text-[#A0A0A0] leading-relaxed">
              An unexpected error occurred while rendering this view. You can try again, or reload the page if the problem persists.
            </p>
            {this.state.error && (
              <p className="text-[10px] text-[#6F6F6F] break-words">
                {this.state.error.message}
              </p>
            )}
            <div className="flex gap-3 justify-center pt-2">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 text-xs uppercase tracking-wider bg-[#16ff4d] hover:bg-[#16ff4d]/90 text-[#090909] font-bold rounded transition-all"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 text-xs uppercase tracking-wider border border-[#222222] hover:bg-[#171717] text-white rounded transition-all"
              >
                Reload Page
              </button>
              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null });
                  window.location.href = "/";
                }}
                className="px-4 py-2 text-xs uppercase tracking-wider border border-red-500/30 text-red-400 hover:bg-red-950/20 rounded transition-all"
              >
                Exit
              </button>
            </div>

          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
