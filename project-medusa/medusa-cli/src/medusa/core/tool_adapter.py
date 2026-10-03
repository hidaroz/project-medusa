from typing import Type, Optional, Dict, Any
from langchain_core.tools import BaseTool as LangChainBaseTool
from pydantic import BaseModel, Field
from medusa.tools.base import BaseTool as MedusaBaseTool

class MedusaToolAdapter(LangChainBaseTool):
    """
    Wraps a Medusa BaseTool into a LangChain BaseTool.
    """
    name: str
    description: str
    medusa_tool: MedusaBaseTool
    
    def __init__(self, medusa_tool: MedusaBaseTool, name: str = None, description: str = ""):
        name = name or medusa_tool.name
        description = description or f"Wrapper for {name}"
        super().__init__(name=name, description=description, medusa_tool=medusa_tool)

    def _run(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Execute the tool synchronously.
        Since Medusa tools are async, we need to run them in an event loop if called synchronously,
        but LangGraph agents usually call tools asynchronously.
        """
        raise NotImplementedError("Medusa tools are async-only. Use ainvoke or arun.")

    async def _arun(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Execute the tool asynchronously.
        """
        return await self.medusa_tool.execute(target, **kwargs)

    # Define input schema
    class InputSchema(BaseModel):
        target: str = Field(description="The target to execute the tool against (IP, URL, etc.)")
        
    args_schema: Type[BaseModel] = InputSchema
